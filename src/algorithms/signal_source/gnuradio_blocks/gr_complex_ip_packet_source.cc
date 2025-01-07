/*!
 * \file gr_complex_ip_packet_source.cc
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


#include "gr_complex_ip_packet_source.h"
#include <gnuradio/io_signature.h>
#include <volk/volk.h>
#include <array>
#include <cstdint>
#include <utility>

#define UDP_PAYLOAD_SIZE_BYTES 8000

#define Gr_Complex_Ip_Packet_Source_RAM_buffers 1000


struct byte_2bit_struct
{
    signed two_bit_sample : 2;  // <- 2 bits wide only
};

/* 4 bytes IP address */
typedef struct gr_ip_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
} gr_ip_address;


/* IPv4 header */
typedef struct gr_ip_header
{
    u_char ver_ihl;          // Version (4 bits) + Internet header length (4 bits)
    u_char tos;              // Type of service
    u_short tlen;            // Total length
    u_short identification;  // Identification
    u_short flags_fo;        // Flags (3 bits) + Fragment offset (13 bits)
    u_char ttl;              // Time to live
    u_char proto;            // Protocol
    u_short crc;             // Header checksum
    gr_ip_address saddr;     // Source address
    gr_ip_address daddr;     // Destination address
    u_int op_pad;            // Option + Padding
} gr_ip_header;


/* UDP header*/
typedef struct gr_udp_header
{
    u_short sport;  // Source port
    u_short dport;  // Destination port
    u_short len;    // Datagram length
    u_short crc;    // Checksum
} gr_udp_header;


Gr_Complex_Ip_Packet_Source::sptr
Gr_Complex_Ip_Packet_Source::make(std::string src_device,
    const std::string &origin_address,
    int udp_port,
    int udp_packet_size,
    int n_baseband_channels,
    const std::string &wire_sample_type,
    size_t item_size,
    bool IQ_swap_)
{
    return gnuradio::get_initial_sptr(new Gr_Complex_Ip_Packet_Source(std::move(src_device),
        origin_address,
        udp_port,
        udp_packet_size,
        n_baseband_channels,
        wire_sample_type,
        item_size,
        IQ_swap_));
}


/*
 * The private constructor
 */
Gr_Complex_Ip_Packet_Source::Gr_Complex_Ip_Packet_Source(std::string src_device,
    __attribute__((unused)) const std::string &origin_address,
    int udp_port,
    int udp_packet_size __attribute__((unused)),
    int n_baseband_channels,
    const std::string &wire_sample_type,
    size_t item_size,
    bool IQ_swap_)
    : gr::sync_block("gr_complex_ip_packet_source",
          gr::io_signature::make(0, 0, 0),
          gr::io_signature::make(1, 4, item_size)),  // 1 to 4 baseband complex channels
      d_stop_flag(false),
      d_src_device(std::move(src_device)),
      descr(nullptr),
      udp_socket_fd_(-1),
      d_sock_raw(0),
      d_udp_port(udp_port),
      d_n_baseband_channels(n_baseband_channels),
      d_IQ_swap(IQ_swap_)
{
    // using queues of smart pointers to preallocated buffers
    d_free_buffers.clear();
    d_used_buffers.clear();
    // preallocate buffers and use queues
    std::cerr << "Allocating memory..\n";
    try
        {
            for (int n = 0; n < Gr_Complex_Ip_Packet_Source_RAM_buffers; n++)
                {
                    d_free_buffers.push(std::make_shared<Gr_Complex_Ip_Packet_Source_Samples>());
                }
        }
    catch (const std::exception &ex)
        {
            std::cout << "ERROR: Problem allocating RAM buffer: " << ex.what() << "\n";
            exit(0);
        }

    if (wire_sample_type == "cbyte")
        {
            d_wire_sample_type = 1;
            d_bytes_per_sample = d_n_baseband_channels * 2;
        }
    else if (wire_sample_type == "c2bits")
        {
            d_wire_sample_type = 5;
            d_bytes_per_sample = d_n_baseband_channels;
        }
    else if (wire_sample_type == "c4bits")
        {
            d_wire_sample_type = 2;
            d_bytes_per_sample = d_n_baseband_channels;
        }
    else if (wire_sample_type == "cfloat")
        {
            d_wire_sample_type = 3;
            d_bytes_per_sample = d_n_baseband_channels * 8;
        }
    else if (wire_sample_type == "ishort")
        {
            d_wire_sample_type = 4;
            d_bytes_per_sample = d_n_baseband_channels * 4;
        }
    else
        {
            std::cout << "Unknown wire sample type\n";
            exit(0);
        }

    output_items_per_work_call = UDP_PAYLOAD_SIZE_BYTES / d_bytes_per_sample;
    set_min_noutput_items(output_items_per_work_call);

    std::cout << "Start Ethernet packet capture\n";
    std::cout << "Overflow events will be indicated by o's\n";
    std::cout << "d_wire_sample_type:" << d_wire_sample_type << '\n';
    std::cout << "output items per work call: " << UDP_PAYLOAD_SIZE_BYTES / d_bytes_per_sample << "\n";
}


// Called by gnuradio to enable drivers, etc for i/o devices.
bool Gr_Complex_Ip_Packet_Source::start()
{
    std::cout << "gr_complex_ip_packet_source START\n";
    open_udp_socket();  // Abre un socket en el puerto especificado
    d_stop_flag = false;
    // start pcap capture thread
    d_pcap_thread = std::thread(&Gr_Complex_Ip_Packet_Source::my_pcap_loop_thread, this);
    return true;
}


// Called by gnuradio to disable drivers, etc for i/o devices.
bool Gr_Complex_Ip_Packet_Source::stop()
{
    std::cout << "gr_complex_ip_packet_source STOP\n";
    d_stop_flag = true;
    if (d_pcap_thread.joinable())
        {
            // pcap_breakloop(descr);
            d_pcap_thread.join();
        }
    close_udp_socket();
    return true;
}


void Gr_Complex_Ip_Packet_Source::open_udp_socket()
{
    udp_socket_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_socket_fd_ < 0)
        {
            std::cerr << "Error creating UDP socket.\n";
            return;
        }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(d_udp_port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(udp_socket_fd_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0)
        {
            std::cerr << "Error binding UDP socket to port " << d_udp_port << "\n";
            close(udp_socket_fd_);
            udp_socket_fd_ = -1;
        }
    else
        {
            std::cout << "Socket bound to UDP port " << d_udp_port << " on interface " << d_src_device << "\n";
        }
}

void Gr_Complex_Ip_Packet_Source::close_udp_socket()
{
    if (udp_socket_fd_ >= 0)
        {
            close(udp_socket_fd_);
            udp_socket_fd_ = -1;
            std::cout << "UDP socket closed.\n";
        }
}

Gr_Complex_Ip_Packet_Source::~Gr_Complex_Ip_Packet_Source()
{
    std::cout << "Stop Ethernet packet capture\n";
}


void Gr_Complex_Ip_Packet_Source::static_pcap_callback(u_char *args, const struct pcap_pkthdr *pkthdr,
    const u_char *packet)
{
    auto *packet_source = reinterpret_cast<Gr_Complex_Ip_Packet_Source *>(args);

    std::lock_guard<std::mutex> lock(packet_source->d_data_mutex);
    const struct ip *ip_header = reinterpret_cast<const struct ip *>(packet + 14);  // 14 bytes Ethernet header
    if (ip_header->ip_p != IPPROTO_UDP) return;

    const struct udphdr *udp_header = reinterpret_cast<const struct udphdr *>(packet + 14 + ip_header->ip_hl * 4);

    if (ntohs(udp_header->uh_dport) != packet_source->d_udp_port)
        {
            return;  // Filtrar solo el puerto especificado
        }

    const uint8_t *payload = reinterpret_cast<const uint8_t *>(packet + 14 + ip_header->ip_hl * 4 + sizeof(udphdr));
    int payload_length_bytes = ntohs(udp_header->uh_ulen) - sizeof(udphdr);

    if (payload_length_bytes > 0)
        {
            if (payload_length_bytes>pkthdr->caplen)
            {
                std::cout<<"SDR UDP packet is fragmented, increase MTU or reduce packet size!\n";
            }else{
                std::shared_ptr<Gr_Complex_Ip_Packet_Source_Samples> current_buffer;
                Gr_Complex_Ip_Packet_Source_Samples *current_samples;
                if (packet_source->d_free_buffers.try_pop(current_buffer)==false)
                {
                    std::cout<<"o";
                }else{
                    current_samples = current_buffer.get();
                    uint8_t *fifo_buff = &current_samples->buffer[0];
                    // write all in a single memcpy
                    //memcpy(fifo_buff, &payload[0], payload_length_bytes);  // size in bytes
                    //uint8_t dummy_buffer[9000];
                    // std::cout<<"pay: "<<payload_length_bytes<<"\n";
                    // std::cout<<"caplen:"<< pkthdr->caplen<<"\n";
                    // std::cout<<"len:"<< pkthdr->len<<"\n";
                    memcpy(fifo_buff, &payload[0], payload_length_bytes);  // size in bytes
                    //for (int n=0;n<payload_length_bytes;n++)
                    //{
                        //std::cout<<"n:"<<n<<": "<<(int)payload[n]<<"\n";
                        //fifo_buff[n]=payload[n];
                    //}
                    //memcpy(fifo_buff, &dummy_buffer[0], payload_length_bytes);  // size in bytes
                    packet_source->d_used_buffers.push(current_buffer);
                }
            }
        }

    //    auto *bridge = reinterpret_cast<Gr_Complex_Ip_Packet_Source *>(args);
    //    bridge->pcap_callback(args, pkthdr, packet);
}

void Gr_Complex_Ip_Packet_Source::my_pcap_loop_thread()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(d_src_device.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!handle)
        {
            std::cerr << "Error opening device " << d_src_device << ": " << errbuf << "\n";
            return;
        }

    std::string filter_exp = "udp dst port " + std::to_string(d_udp_port);
    struct bpf_program filter;
    if (pcap_compile(handle, &filter, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &filter) == -1)
        {
            std::cerr << "Error setting filter: " << pcap_geterr(handle) << "\n";
            pcap_close(handle);
            return;
        }

    while (!d_stop_flag)
        {
            pcap_dispatch(handle, 10, static_pcap_callback, reinterpret_cast<u_char *>(this));
        }

    pcap_close(handle);
}


void Gr_Complex_Ip_Packet_Source::demux_samples(const gr_vector_void_star &output_items, int num_samples_readed)
{
    std::shared_ptr<Gr_Complex_Ip_Packet_Source_Samples> current_buffer;
    Gr_Complex_Ip_Packet_Source_Samples *current_samples;

    d_used_buffers.wait_and_pop(current_buffer);
    current_samples = current_buffer.get();

    uint8_t *fifo_buff = &current_samples->buffer[0];

    if (d_wire_sample_type == 5)
        {
            // interleaved 2-bit I 2-bit Q samples packed in bytes: 1 byte -> 2 complex samples
            int nsample = 0;
            byte_2bit_struct sample{};  // <- 2 bits wide only
            int real;
            int imag;
            for (int nbyte = 0; nbyte < num_samples_readed / 2; nbyte++)
                {
                    for (const auto &output_item : output_items)
                        {
                            // Read packed input sample (1 byte = 2 complex samples)
                            // *     Packing Order
                            // *     Most Significant Nibble  - Sample n
                            // *     Least Significant Nibble - Sample n+1
                            // *     Bit Packing order in Nibble Q1 Q0 I1 I0
                            // normal
                            int8_t c = fifo_buff[nbyte];

                            // Q[n]
                            sample.two_bit_sample = (c >> 6) & 3;
                            imag = (2 * static_cast<int8_t>(sample.two_bit_sample) + 1);
                            // I[n]
                            sample.two_bit_sample = (c >> 4) & 3;
                            real = (2 * static_cast<int8_t>(sample.two_bit_sample) + 1);

                            if (d_IQ_swap)
                                {
                                    static_cast<gr_complex *>(output_item)[nsample * 2] = gr_complex(real, imag);
                                }
                            else
                                {
                                    static_cast<gr_complex *>(output_item)[nsample * 2] = gr_complex(imag, real);
                                }


                            // Q[n+1]
                            sample.two_bit_sample = (c >> 2) & 3;
                            imag = (2 * static_cast<int8_t>(sample.two_bit_sample) + 1);
                            // I[n+1]
                            sample.two_bit_sample = c & 3;
                            real = (2 * static_cast<int8_t>(sample.two_bit_sample) + 1);

                            if (d_IQ_swap)
                                {
                                    static_cast<gr_complex *>(output_item)[nsample * 2 + 1] = gr_complex(real, imag);
                                }
                            else
                                {
                                    static_cast<gr_complex *>(output_item)[nsample * 2 + 1] = gr_complex(imag, real);
                                }
                        }
                    nsample++;
                }
        }
    else
        {
            int nbyte = 0;
            for (int n = 0; n < num_samples_readed; n++)
                {
                    switch (d_wire_sample_type)
                        {
                        case 1:  // interleaved byte samples
                            for (const auto &output_item : output_items)
                                {
                                    int8_t real;
                                    int8_t imag;
                                    real = fifo_buff[nbyte++];
                                    imag = fifo_buff[nbyte++];
                                    if (d_IQ_swap)
                                        {
                                            static_cast<gr_complex *>(output_item)[n] = gr_complex(real, imag);
                                        }
                                    else
                                        {
                                            static_cast<gr_complex *>(output_item)[n] = gr_complex(imag, real);
                                        }
                                }
                            break;
                        case 2:  // 4-bit samples
                            for (const auto &output_item : output_items)
                                {
                                    int8_t real;
                                    int8_t imag;
                                    uint8_t tmp_char2;
                                    tmp_char2 = fifo_buff[nbyte] & 0x0F;
                                    if (tmp_char2 >= 8)
                                        {
                                            real = 2 * (tmp_char2 - 16) + 1;
                                        }
                                    else
                                        {
                                            real = 2 * tmp_char2 + 1;
                                        }
                                    tmp_char2 = fifo_buff[nbyte++] >> 4;
                                    tmp_char2 = tmp_char2 & 0x0F;
                                    if (tmp_char2 >= 8)
                                        {
                                            imag = 2 * (tmp_char2 - 16) + 1;
                                        }
                                    else
                                        {
                                            imag = 2 * tmp_char2 + 1;
                                        }
                                    if (d_IQ_swap)
                                        {
                                            static_cast<gr_complex *>(output_item)[n] = gr_complex(imag, real);
                                        }
                                    else
                                        {
                                            static_cast<gr_complex *>(output_item)[n] = gr_complex(real, imag);
                                        }
                                }
                            break;
                        case 3:  // interleaved float samples
                            for (const auto &output_item : output_items)
                                {
                                    float real;
                                    float imag;
                                    memcpy(&real, &fifo_buff[nbyte], sizeof(real));
                                    nbyte += 4;  // Four bytes in float
                                    memcpy(&imag, &fifo_buff[nbyte], sizeof(imag));
                                    nbyte += 4;  // Four bytes in float
                                    if (d_IQ_swap)
                                        {
                                            static_cast<gr_complex *>(output_item)[n] = gr_complex(real, imag);
                                        }
                                    else
                                        {
                                            static_cast<gr_complex *>(output_item)[n] = gr_complex(imag, real);
                                        }
                                }
                            break;
                        case 4:  // interleaved short samples
                            for (const auto &output_item : output_items)
                                {
                                    int16_t real;
                                    int16_t imag;
                                    memcpy(&real, &fifo_buff[nbyte], sizeof(real));
                                    nbyte += 2;  // two bytes in short
                                    memcpy(&imag, &fifo_buff[nbyte], sizeof(imag));
                                    nbyte += 2;  // two bytes in short
                                    if (d_IQ_swap)
                                        {
                                            static_cast<gr_complex *>(output_item)[n] = gr_complex(real, imag);
                                        }
                                    else
                                        {
                                            static_cast<gr_complex *>(output_item)[n] = gr_complex(imag, real);
                                        }
                                }
                            break;
                        default:
                            std::cout << "Unknown wire sample type\n";
                            exit(0);
                        }
                }
        }
    d_free_buffers.push(current_buffer);
}


int Gr_Complex_Ip_Packet_Source::work(int noutput_items,
    __attribute__((unused)) gr_vector_const_void_star &input_items,
    gr_vector_void_star &output_items)
{
    if (output_items.size() > static_cast<uint64_t>(d_n_baseband_channels))
        {
            std::cout << "Configuration error: more baseband channels connected than available in the UDP source\n";
            exit(0);
        }

    demux_samples(output_items, output_items_per_work_call);

    for (uint64_t n = 0; n < output_items.size(); n++)
        {
            produce(static_cast<int>(n), output_items_per_work_call);
        }
    return this->WORK_CALLED_PRODUCE;
}
