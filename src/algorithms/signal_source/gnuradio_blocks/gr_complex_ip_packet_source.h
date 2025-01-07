/*!
 * \file gr_complex_ip_packet_source.h
 *
 * \brief Receives ip frames containing samples in UDP frame encapsulation
 * using a high performance packet capture library (libpcap)
 * \author Javier Arribas jarribas (at) cttc.es
 *
 * -----------------------------------------------------------------------------
 *
 * GNSS-SDR is a Global Navigation Satellite System software-defined receiver.
 * This file is part of GNSS-SDR.
 *
 * Copyright (C) 2010-2020  (see AUTHORS file for a list of contributors)
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * -----------------------------------------------------------------------------
 */


#ifndef GNSS_SDR_GR_COMPLEX_IP_PACKET_SOURCE_H
#define GNSS_SDR_GR_COMPLEX_IP_PACKET_SOURCE_H

#include "concurrent_queue.h"
#include "gnss_block_interface.h"
#include <gnuradio/sync_block.h>
#include <arpa/inet.h>
#include <atomic>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <string>
#include <sys/ioctl.h>
#include <thread>

class Gr_Complex_Ip_Packet_Source_Samples
{
public:
    uint8_t buffer[9000];  // MAX IP packet size
};


/** \addtogroup Signal_Source
 * \{ */
/** \addtogroup Signal_Source_gnuradio_blocks signal_source_gr_blocks
 * GNU Radio blocks for signal sources.
 * \{ */


class Gr_Complex_Ip_Packet_Source : virtual public gr::sync_block
{
public:
    using sptr = gnss_shared_ptr<Gr_Complex_Ip_Packet_Source>;
    static sptr make(std::string src_device,
        const std::string &origin_address,
        int udp_port,
        int udp_packet_size,
        int n_baseband_channels,
        const std::string &wire_sample_type,
        size_t item_size,
        bool IQ_swap_);
    Gr_Complex_Ip_Packet_Source(std::string src_device,
        const std::string &origin_address,
        int udp_port,
        int udp_packet_size,
        int n_baseband_channels,
        const std::string &wire_sample_type,
        size_t item_size,
        bool IQ_swap_);
    ~Gr_Complex_Ip_Packet_Source();

    // Called by gnuradio to enable drivers, etc for i/o devices.
    bool start();

    // Called by gnuradio to disable drivers, etc for i/o devices.
    bool stop();

    // Where all the action really happens
    int work(int noutput_items,
        gr_vector_const_void_star &input_items,
        gr_vector_void_star &output_items);

private:
    void demux_samples(const gr_vector_void_star &output_items, int num_samples_readed);
    void my_pcap_loop_thread();
    static void static_pcap_callback(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet);
    void open_udp_socket();
    void close_udp_socket();

    std::atomic<bool> d_stop_flag;
    std::thread d_pcap_thread;
    std::string d_src_device;
    std::string d_origin_address;

    std::mutex d_data_mutex;
    // using queues of smart pointers to preallocated buffers
    Concurrent_Queue<std::shared_ptr<Gr_Complex_Ip_Packet_Source_Samples>> d_free_buffers;
    Concurrent_Queue<std::shared_ptr<Gr_Complex_Ip_Packet_Source_Samples>> d_used_buffers;

    pcap_t *descr;  // ethernet pcap device descriptor
    int udp_socket_fd_;

    int d_sock_raw;
    int d_udp_port;
    int d_n_baseband_channels;
    int d_wire_sample_type;
    float d_bytes_per_sample;
    int output_items_per_work_call;
    bool d_IQ_swap;
};


/** \} */
/** \} */
#endif  //  GNSS_SDR_GR_COMPLEX_IP_PACKET_SOURCE_H
