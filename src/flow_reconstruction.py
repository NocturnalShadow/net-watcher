import threading
import queue
import time
import gc

from scapy.all import Ether, IP, IPv6, TCP, UDP, Raw, RawPcapReader, sniff, conf

from flow_features import calculate_features, first_packet_time, last_packet_time
from enums import Direction, FlowTerminationReason, Protocol
from logging_utils import log

# TODO: consider different timeout values for different protocols (e.g. TCP vs UDP)
# TODO: Analyze dataset to: 
# - determine the optimal values for timeouts
# - check the maximum number of simultaneous unique UDP flows for the timeout parameter (to determine the queue size)

class FlowReconstructor:
    def __init__(self, output_queue=queue.Queue(), **kwargs):
        self.idle_timeout = int(kwargs.get("idle_timeout", 600))
        self.activity_timeout = int(kwargs.get("activity_timeout", 1000))
        self.net_interface = kwargs.get("net_interface", conf.iface)
        
        assert self.idle_timeout > 0, "Idle timeout must be greater than 0"
        assert self.activity_timeout > 0, "Activity timeout must be greater than 0"
        assert self.idle_timeout < self.activity_timeout, "Idle timeout must be less than activity timeout"

        self.tcp_termination_grace_period = 1.0          # period for which new packets are allowed to join the finalizing TCP flow
        self.tcp_termination_check_interval = 5.0        # interval at which the list of finalizing TCP flows is checked for termination
        self.timeout_termination_check_interval = 60.0   # interval at which the list of active flows is checked for termination by timeout

        log.info(f"""Flow Reconstructor configuration:
                                idle_timeout={self.idle_timeout}, activity_timeout={self.activity_timeout},
                                tcp_termination_grace_period={self.tcp_termination_grace_period}, tcp_termination_check_interval={self.tcp_termination_check_interval},
                                timeout_termination_check_interval={self.timeout_termination_check_interval},
                                net_interface={self.net_interface}""")

        self.current_time        = 0
        self.active_flows        = {}
        self.finalizing_flows    = {} # NOTE: Should be thread-safe according to https://docs.python.org/3/glossary.html#term-GIL
        self.terminated_flows    = queue.Queue(maxsize=2000)    # terminated flows whose features to be calculated 
        self.packet_queue        = queue.Queue(maxsize=30000)   # 1k -> ~1.85 MB memory footprint <- Maxsize * (MTU + size(Scapy Ether)). Where MTU ~= 1500 + 20 bytes, size(Scapy Ether) = 344
        self.reconstructed_flows = output_queue                 # when flow reconstruction is done, the flows are put here

        self.terminated_flows.queue_was_full    = False
        self.packet_queue.queue_was_full        = False
        self.reconstructed_flows.queue_was_full = False

        self.processed_packets_count    = 0
        self.reconstructed_flows_count  = 0 # TODO: sometimes this stat is just a bit off
        self.last_timeout_check         = 0 # last time when active flows were checked for termination by timeout

        # --- STAISTICS ---
        self.collect_stats = bool(kwargs.get("collect_stats", True))
        self.stats_log_step = int(kwargs.get("stats_log_step", 100_000))
        self.start_time = time.time()
        self.prev_packet_time = 0
        self.packets_count = 0
        self.out_of_order_packets_count = 0
        self.timeline_shift_terminations_count  = 0
        self.discarded_items_count = {}
        # -------------

    def __enter__(self):
        # Processes incoming packets and organizes them into flows
        self.packet_processor_thread = threading.Thread(target=self.packet_processor)
        self.packet_processor_thread.daemon = True
        self.packet_processor_thread.start()
    
        self.stop_event = threading.Event()
        self.terminator_trigger_event = threading.Event()
        # Terminates finalizing flows (which entered the finalizing state due to FIN or RST flags)
        self.finalizing_flows_terminator_thread = threading.Thread(target=self.finalizing_flows_terminator, args=(self.stop_event,self.terminator_trigger_event))
        self.finalizing_flows_terminator_thread.daemon = True
        self.finalizing_flows_terminator_thread.start()

        # Calculates features for terminated flows
        self.terminated_flows_processor_thread = threading.Thread(target=self.terminated_flows_processor)
        self.terminated_flows_processor_thread.daemon = True
        self.terminated_flows_processor_thread.start()

        self.start_time = time.time()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.packet_queue.put(None)
        self.packet_processor_thread.join()

        self.stop_event.set()
        self.finalizing_flows_terminator_thread.join()

        # Terminate remaining active flows
        for flow_id in list(self.active_flows.keys()):
            self.terminate_flow(self.active_flows, flow_id, "unknown")

        self.terminated_flows.put(None)
        self.terminated_flows_processor_thread.join()

        # Should never happen
        if self.active_flows:
            log.warning(f"{len(self.active_flows)} active flows were abandoned.")
        if self.finalizing_flows:
            log.warning(f"{len(self.finalizing_flows)} finalizing flows were abandoned.")

        if self.collect_stats:
            self.log_statistics()

    def update_stats(self, packet):
        self.packets_count += 1
        
        if packet.time < self.prev_packet_time:
            self.out_of_order_packets_count += 1
        self.prev_packet_time = packet.time

        if self.packets_count % self.stats_log_step == 0:
            self.log_statistics()

    def online(self):
        log.info("Reconstructing flows from live traffic...")
        def packet_handler(packet):
            self.enqueue_nowait(self.packet_queue, packet, "packet")
            if self.collect_stats:
                self.update_stats(packet)

        assert self.net_interface is not None, "Network interface must be specified for live traffic processing"
        sniff(filter="tcp", prn=packet_handler, iface=self.net_interface, store=0)

    def offline(self, source):
        log.info(f"Reconstructing flows from file: {source} ...")

        # TODO: solve meta.sec issue with pcapng files
        for pkt_data, pkt_meta in RawPcapReader(source):
            packet = Ether(pkt_data)
            packet.time = pkt_meta.sec + pkt_meta.usec / 1_000_000
            
            # TODO: allow different protocols
            if TCP in packet:
                self.packet_queue.put(packet)
            else:
                continue
            
            if self.collect_stats:
                self.update_stats(packet)

    def packet_processor(self):
        while True:
            packet = self.packet_queue.get()
            if packet is None:
                return

            self.current_time = packet.time
            if TCP in packet:
                if self.preprocess(packet):
                    self.process_tcp(packet)
            elif UDP in packet:
                if self.preprocess(packet):
                    self.process_universal(packet)

            # in case of out-of-order packets we reset the last_timeout_check to the timeline of the new packet
            self.last_timeout_check = min(self.current_time, self.last_timeout_check) 
            if self.current_time - self.last_timeout_check > self.timeout_termination_check_interval:
                self.last_timeout_check = self.current_time
                self.terminate_timouted_flows()

            self.processed_packets_count += 1

    def preprocess(self, packet):
        # TODO: debug the case for non-TCP or UDP packets
        if IP in packet:
            packet.src_ip = packet[IP].src
            packet.dst_ip = packet[IP].dst
            packet.protocol = packet[IP].proto
        elif IPv6 in packet:
            packet.src_ip = packet[IPv6].src
            packet.dst_ip = packet[IPv6].dst
            packet.protocol = packet[IPv6].nh
        else:
            return False

        if packet.protocol not in [Protocol.TCP.value, Protocol.UDP.value]:
            packet.sport = 0
            packet.dport = 0

        if Raw not in packet:
            packet.payload_bytes = 0
        else:
            packet.payload_bytes = len(packet.load)
            # packet[TCP].remove_payload()

            # Find the last layer before Raw and remove it's payload
            current_layer = packet
            while current_layer.payload:
                if current_layer.payload.name == "Raw":
                    current_layer.remove_payload()
                    break
                current_layer = current_layer.payload

        return True

    def process_tcp(self, packet):
        packet_tcp = packet[TCP]
        flow_id = (packet.src_ip, packet.dst_ip, packet.sport, packet.dport, packet.protocol)
        flow = self.find_flow(flow_id, packet)
        if flow is None:
            # No connection found, we need to start a new flow
            flow = self.initiate_new_flow(flow_id, packet)
        elif packet_tcp.flags.S and (flow_id in self.finalizing_flows):
            # This packet tries to establish a new connection, while existing one is being finalized
            # We need to terminate the current flow and start a new one
            # self.terminate_finalizing_flow(flow_id) # TODO: reproduce Queue.Full exception + no ability to stop the process
            self.terminate_flow(self.finalizing_flows, flow_id)
            flow = self.initiate_new_flow(flow_id, packet)     
        else:
            # TODO: Check if the timeout for the active flow was expired
            flow["packets"].append(packet)

        if packet_tcp.flags.F:
            self.finalize_flow(flow_id, "FIN")
        elif packet_tcp.flags.R:
            self.finalize_flow(flow_id, "RST")

    def process_universal(self, packet):
        flow_id = (packet.src_ip, packet.dst_ip, packet.sport, packet.dport, packet.protocol)
        flow = self.find_flow(flow_id, packet)
        if flow is None:
            # No connection found, we need to start a new flow
            flow = self.initiate_new_flow(flow_id, packet)
        else:
            # TODO: Check if the timeout for the active flow was expired
            flow["packets"].append(packet)

    def find_flow(self, flow_id, packet):
        def find_flow_by_id(flows, flow_id, packet):
            flow = flows.get(flow_id)
            if flow is None:
                # Check for reversed flow
                flow_id_alt = (flow_id[1], flow_id[0], flow_id[3], flow_id[2], flow_id[4])
                flow = flows.get(flow_id_alt)
                if flow is not None:
                    flow_id = flow_id_alt
                    packet.direction = Direction.BACKWARD
            else:
                packet.direction = Direction.FORWARD
            return flow
    
        flow = find_flow_by_id(self.active_flows, flow_id, packet)
        if flow is None:
            flow = find_flow_by_id(self.finalizing_flows, flow_id, packet)
        return flow

    def initiate_new_flow(self, flow_id, packet):
        log.debug(f"Initiating new flow {flow_id}")
        flow = {
            "packets": [packet],
            "termination_reason": FlowTerminationReason.UNKNOWN.value,
        }

        self.active_flows[flow_id] = flow
        packet.direction = Direction.FORWARD
        return flow

    # Only applicable to TCP flows
    # FLow is finalized when the first FIN or RST flag is encountered
    def finalize_flow(self, flow_id, reason):
        # Skip if the flow is not active (means already finalizing or terminated)
        flow = self.active_flows.pop(flow_id, None)
        if flow is not None:
            log.debug(f"Finalizing flow {flow_id} ({reason})")
            self.finalizing_flows[flow_id] = flow
            flow["finalization_time"] = last_packet_time(flow)
            flow["finalization_time_system"] = time.time()
            flow["termination_reason"] = reason

            # Trigger finalizing_flows_terminator preemtively, 
            # so that terminated_flow_processor can start working on it ASAP
            if len(self.finalizing_flows) >= self.terminated_flows.maxsize * 0.25:
                self.terminator_trigger_event.set()

    def terminate_timouted_flows(self):
        for flow_id in list(self.active_flows.keys()):
            flow = self.active_flows[flow_id]
            flow_idle_time = self.current_time - last_packet_time(flow)
            flow_activity_time = self.current_time - first_packet_time(flow)
            if flow_idle_time > self.idle_timeout:
                self.terminate_flow(self.active_flows, flow_id, "idle_timeout")
            elif flow_activity_time > self.activity_timeout:
                self.terminate_flow(self.active_flows, flow_id, "activity_timeout")
            elif flow_activity_time < 0: # out-of-order packets shifted the timeline
                self.terminate_flow(self.active_flows, flow_id, "unknown")
                self.timeline_shift_terminations_count += 1

    def terminate_finalizing_flows(self):
        for flow_id in list(self.finalizing_flows.keys()):
            flow = self.finalizing_flows[flow_id]
            if self.current_time - flow["finalization_time"] > self.tcp_termination_grace_period \
            or time.time() - flow["finalization_time_system"] > self.tcp_termination_grace_period:
                self.terminate_flow(self.finalizing_flows, flow_id)

    def terminate_flow(self, flows, flow_id, reason=None):
        flow = flows.pop(flow_id, None)
        if flow is not None:
            if reason is not None:
                flow["termination_reason"] = reason
            log.debug(f"Terminating flow {flow_id}")
            self.enqueue_nowait(self.terminated_flows, flow, "terminated flow")
        else:
            log.error(f"ERROR: Flow {flow_id} not found among flows.")
    
    def finalizing_flows_terminator(self, stop_event, terminator_trigger_event):
        while not stop_event.is_set():
            terminator_trigger_event.wait(self.tcp_termination_check_interval)
            terminator_trigger_event.clear()
            self.terminate_finalizing_flows()
        self.terminate_finalizing_flows()

    def terminated_flows_processor(self):
        while True:
            flow = self.terminated_flows.get()
            if flow is None:
                return
            flow = calculate_features(flow)
            self.enqueue_nowait(self.reconstructed_flows, flow, "reconstructed flow")

            self.reconstructed_flows_count += 1

    def enqueue_nowait(self, _queue, item, item_name="item"):
        try:
            _queue.put(item, block=False)
            if _queue.queue_was_full:
                log.warning(f"The queue of {item_name}s is no longer full: discarded {_queue.discarded_items_count} items total.")
                _queue.queue_was_full = False
                _queue.discarded_items_count = 0
        except queue.Full:
            if not _queue.queue_was_full:
                log.warning(f"The queue of {item_name}s is full: new items might be discarded!")
                _queue.queue_was_full = True
            _queue.discarded_items_count = getattr(_queue, "discarded_items_count", 0) + 1

            if self.collect_stats:
                self.discarded_items_count[item_name] = self.discarded_items_count.get(item_name, 0) + 1

    def log_statistics(self):
        try:
            log.info("=================================================================")
            log.info("================= Flow Reconstructor Statistics =================")
            log.info("=================================================================")
            log.info(f"Overall:")
            log.info(f" Time elapsed: {time.time() - self.start_time}")
            log.info(f" Packets processed: {self.processed_packets_count}")
            log.info(f" Flows reconstructed: {self.reconstructed_flows_count}")
            for item, count in self.discarded_items_count.items():
                log.info(f" Discarded {item}s: {count}")
            log.info(f"Current:")
            # log.info(f"Out of order packets: {self.out_of_order_packets_count}")
            # log.info(f"Timeline shift terminations count: {self.timeline_shift_terminations_count}")
            log.info(f" Active flows: {len(self.active_flows)}, Finalizing flows: {len(self.finalizing_flows)}")
            log.info(f" Packet in queue: {self.packet_queue.qsize()}")
            log.info(f" Terminated flows queue: {self.terminated_flows.qsize()}")
            log.info(f" Output flows in queue: {self.reconstructed_flows.qsize()}")
            log.info(f" Objects in memory: {len(gc.get_objects())}")
        except Exception as e:
            log.warning(f"Failed to log statistics: {e}", exc_info=False)

if __name__ == "__main__":
    # TODO: add unit tests

    with FlowReconstructor() as reconstructor:
        reconstructor.offline("pcap/benign/benign.pcap")

    # with FlowReconstructor() as reconstructor:
    #     reconstructor.offline("pcap/malicious/IRC.pcap")