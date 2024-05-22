#include "../include/ft_nmap.h"



static void process_results(const t_port_data port_data, const t_scan_type *scan_types, const uint8_t total_scans, char *dest) {
    static const char   scan_type_string[6][5] = SCAN_TYPE_STRING;
    static const char   response_result_string[6][20] = RESPONSE_RESULT_STRING;
    char                last_line_results[64] = "";
    uint8_t             total_length = 0, line_length = 0, line_index = 0, scans_index = 0;

    if (total_scans == 6) {
        for (; scans_index < 3; ++scans_index) {
            total_length += sprintf(dest + total_length, "%s(%s) ", scan_type_string[scans_index], response_result_string[port_data.response[scans_index]]);
        }
        total_length += sprintf(dest + total_length, FINAL_DISPLAY_NEWLINE);
        for (; scans_index < 5; ++scans_index) {
            total_length += sprintf(dest + total_length, "%s(%s) ", scan_type_string[scans_index], response_result_string[port_data.response[scans_index]]);
        }
        total_length += sprintf(dest + total_length, FINAL_DISPLAY_NEWLINE);
        sprintf(last_line_results, "%s(%s)", scan_type_string[scans_index], response_result_string[port_data.response[scans_index]]);
        sprintf(dest + total_length, "%-36s", last_line_results);
    } else {
        for (; scans_index < 6; ++scans_index) {
            if (scan_types[scans_index]) {
                if (line_index == total_scans / 2) {
                    for (; scans_index < 6; ++scans_index) {
                        if (scan_types[scans_index]) {
                            line_length += sprintf(last_line_results + line_length, "%s(%s) ",
                                scan_type_string[scans_index], response_result_string[port_data.response[scans_index]]);
                        }
                    }
                    sprintf(dest + total_length, "%-36s", last_line_results);
                    break ;
                } else {
                    total_length += sprintf(dest + total_length, "%s(%s)%s",
                        scan_type_string[scans_index], response_result_string[port_data.response[scans_index]], scans_index % 2 == 0 ? " " : "");
                    if (scans_index % 2 == 1) {
                        total_length += sprintf(dest + total_length, "%s", FINAL_DISPLAY_NEWLINE);
                        ++line_index;
                    }
                }
            }
        }
    }
}

static void display_port_data(const t_port_data port_data, const t_scan_type *scan_types, const uint8_t total_scans) {
    static const char   response_result_string[6][20] = RESPONSE_RESULT_STRING;
    char                results[256] = "";

    process_results(port_data, scan_types, total_scans, (char *)results);
    printf(
        "%-9d%-27s" \
        "%s%s\n",
        port_data.port, *port_data.service ? port_data.service : "Unassigned",
        results, response_result_string[port_data.conclusion]
    );
}

static void list_unopened_ports(const t_port_data *port_data, const uint16_t unopened_ports, const t_scan_type *scan_types, const uint8_t total_scans) {
    printf(
        "\nClosed/Filtered/Unfiltered ports:\n" \
        "Port     Service Name (if applicable) Results                           Conclusion\n" \
        "------------------------------------------------------------------------------------------------------------\n"
    );

    for (int i = 0, ports_displayed = 0; ports_displayed < unopened_ports; ++i) {
        if (port_data[i].port && port_data[i].conclusion != OPEN) {
            display_port_data(port_data[i], scan_types, total_scans);
            ++ports_displayed;
        }
    }
}

static void list_opened_ports(const t_port_data *port_data, const uint16_t opened_ports, const t_scan_type *scan_types, const uint8_t total_scans) {
    printf(
        "\nOpen ports:\n" \
        "Port     Service Name (if applicable) Results                           Conclusion\n" \
        "------------------------------------------------------------------------------------------------------------\n"
    );

    for (int i = 0, ports_displayed = 0; ports_displayed < opened_ports; ++i) {
        if (i < 100)
        if (port_data[i].conclusion == OPEN) {
            display_port_data(port_data[i], scan_types, total_scans);
            ++ports_displayed;
        }
    }
}

void display_final_data(t_nmap *nmap, struct timeval scan_start_time) {
    struct timeval  currtime, diff;
    uint8_t         total_scans = 0;

    gettimeofday(&currtime, 0);
    timersub(&currtime, &scan_start_time, &diff);
    printf(
        "Scan took %ld.%ld secs\n" \
        "IP address: %s\n", \
        diff.tv_sec, diff.tv_usec,
        inet_ntoa(((struct sockaddr_in)nmap->destaddr).sin_addr)
    );

    for (int i = 0; i < 6; ++i) {
        if (nmap->args.scans[i]) {
            ++total_scans;
        }
    }

    if (nmap->args.opened_ports) {
        list_opened_ports(nmap->args.port_data, nmap->args.opened_ports, nmap->args.scans, total_scans);
    }

    if (nmap->args.total_ports > nmap->args.opened_ports) {
        list_unopened_ports(nmap->args.port_data, nmap->args.total_ports - nmap->args.opened_ports, nmap->args.scans, total_scans);
    }
}