from joblib import load
import pandas as pd
# import tkinter as tk

# Multi-class features selected using SelectPercentile feature extraction.
MC_FEATURES = ['duration', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
               'logged_in', 'root_shell', 'num_file_creations', 'num_shells',
               'is_guest_login', 'count', 'srv_count', 'serror_rate',
               'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
               'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
               'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
               'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
               'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
               'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
               'dst_host_srv_rerror_rate', 'protocol_type_icmp',
               'protocol_type_tcp', 'protocol_type_udp', 'service_IRC',
               'service_Z39_50', 'service_auth', 'service_bgp', 'service_courier',
               'service_csnet_ns', 'service_ctf', 'service_daytime',
               'service_discard', 'service_domain', 'service_domain_u',
               'service_echo', 'service_eco_i', 'service_ecr_i', 'service_efs',
               'service_exec', 'service_finger', 'service_ftp',
               'service_ftp_data', 'service_gopher', 'service_hostnames',
               'service_http', 'service_http_443', 'service_imap4',
               'service_iso_tsap', 'service_klogin', 'service_kshell',
               'service_ldap', 'service_link', 'service_login', 'service_mtp',
               'service_name', 'service_netbios_dgm', 'service_netbios_ns',
               'service_netbios_ssn', 'service_netstat', 'service_nnsp',
               'service_nntp', 'service_ntp_u', 'service_other', 'service_pop_2',
               'service_pop_3', 'service_printer', 'service_private',
               'service_remote_job', 'service_rje', 'service_smtp',
               'service_sql_net', 'service_ssh', 'service_sunrpc',
               'service_supdup', 'service_systat', 'service_telnet',
               'service_time', 'service_urp_i', 'service_uucp',
               'service_uucp_path', 'service_vmnet', 'service_whois', 'flag_OTH',
               'flag_REJ', 'flag_RSTO', 'flag_RSTOS0', 'flag_RSTR', 'flag_S0',
               'flag_S1', 'flag_S2', 'flag_S3', 'flag_SF', 'flag_SH']

# Binary features selected using SelectPercentile feature extraction.
B_FEATURES = ['duration', 'wrong_fragment', 'logged_in', 'is_guest_login',
              'count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
              'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
              'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
              'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
              'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
              'dst_host_serror_rate', 'dst_host_srv_serror_rate',
              'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
              'protocol_type_icmp', 'protocol_type_udp', 'service_IRC',
              'service_Z39_50', 'service_auth', 'service_bgp', 'service_courier',
              'service_csnet_ns', 'service_ctf', 'service_daytime',
              'service_discard', 'service_domain', 'service_domain_u',
              'service_echo', 'service_eco_i', 'service_ecr_i', 'service_efs',
              'service_exec', 'service_finger', 'service_ftp_data',
              'service_gopher', 'service_hostnames', 'service_http',
              'service_http_443', 'service_imap4', 'service_iso_tsap',
              'service_klogin', 'service_kshell', 'service_ldap', 'service_link',
              'service_login', 'service_mtp', 'service_name',
              'service_netbios_dgm', 'service_netbios_ns', 'service_netbios_ssn',
              'service_netstat', 'service_nnsp', 'service_nntp', 'service_ntp_u',
              'service_pop_2', 'service_private', 'service_rje', 'service_smtp',
              'service_sql_net', 'service_ssh', 'service_sunrpc',
              'service_supdup', 'service_systat', 'service_telnet',
              'service_time', 'service_urp_i', 'service_uucp',
              'service_uucp_path', 'service_vmnet', 'service_whois', 'flag_REJ',
              'flag_RSTO', 'flag_RSTOS0', 'flag_RSTR', 'flag_S0', 'flag_S1',
              'flag_SF', 'flag_SH']


# def ids_gui(samples):
#     root = tk.Tk()
#     root.title('IDS')
#
#     root.geometry('500x500')
#     root.resizable(False, False)
#
#     normal_btn = tk.Button(root, text='NORMAL PACKET', command=lambda: get_sample(samples['normal']))
#     dos_btn = tk.Button(root, text='DOS PACKET', command=lambda: get_sample(samples['dos']))
#     probe_btn = tk.Button(root, text='PROBE PACKET', command=lambda: get_sample(samples['probe']))
#     u2r_btn = tk.Button(root, text='U2R PACKET', command=lambda: get_sample(samples['u2r']))
#     r2l_btn = tk.Button(root, text='R2L PACKET', command=lambda: get_sample(samples['r2l']))
#
#     normal_btn.pack(pady=5)
#     dos_btn.pack(pady=5)
#     probe_btn.pack(pady=5)
#     u2r_btn.pack(pady=5)
#     r2l_btn.pack(pady=5)
#
#     root.mainloop()


# Loads packet samples and returns an array.
def load_data_samples():
    normal = pd.read_csv('sampled_data/NORMAL.csv')
    dos = pd.read_csv('sampled_data/DOS.csv')
    probe = pd.read_csv('sampled_data/PROBE.csv')
    u2r = pd.read_csv('sampled_data/U2R.csv')
    r2l = pd.read_csv('sampled_data/R2L.csv')

    return [normal, dos, probe, u2r, r2l]


# Drops the label column from the samples.
def drop_labels(datasets):
    for dataset in datasets:
        dataset.drop('label', axis=1, inplace=True)


# Gets prediction using specified model.
def get_prediction(model, packet):
    if model == MC_MODEL:
        filtered_packet = packet[MC_FEATURES]  # Extracts the relevant features
    else:
        filtered_packet = packet[B_FEATURES]
    filtered_packet_vals = filtered_packet.values
    prediction = model.predict(filtered_packet_vals)

    return prediction[0]


# Gets a random sample from the specified dataset and returns the prediction.
def classify_packet(index):
    packet = SAMPLES[index].sample()  # Gets a random sample from the specified dataset
    mc_prediction = get_prediction(MC_MODEL, packet)
    b_prediction = get_prediction(B_MODEL, packet)

    if mc_prediction == 'NORMAL' and b_prediction == 'NORMAL':  # both models NORMAL
        result = "Packet is most likely NORMAL."
    elif mc_prediction != 'NORMAL':  # mc = not NORMAL
        result = f"{mc_prediction} detected."
    else:  # mc = NORMAL, b = ABNORMAL
        result = "ABNORMAL packet detected."

    return f"[*] {result} \n"


# Load models
MC_MODEL = load('sp_rf_80.joblib')
B_MODEL = load('sp_rf_b_87.joblib')

# Load data samples and drop labels
SAMPLES = load_data_samples()
drop_labels(SAMPLES)


# Runs the program.
def main():
    actions = ['1', '2', '3', '4', '5', '0']  # Valid actions
    while True:
        command = input('Select type of packet or exit with [0]: \n'
                        '[1] Normal\n'
                        '[2] DOS\n'
                        '[3] PROBE\n'
                        '[4] U2R\n'
                        '[5] R2L\n\n'
                        'Selection: ')
        if command in actions:
            if command == '1':  # Normal packet
                print(classify_packet(0))
            elif command == '2':  # Dos packet
                print(classify_packet(1))
            elif command == '3':  # Probe packet
                print(classify_packet(2))
            elif command == '4':  # U2R packet
                print(classify_packet(3))
            elif command == '5':  # R2L packet
                print(classify_packet(4))
            elif command == '0':  # Exit program
                print('Exit...')
                exit(1)
        else:
            print('Invalid Command. Try again.\n\n')
            continue


if __name__ == '__main__':
    main()
