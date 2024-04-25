import argparse
from joblib import load
import pandas as pd
import dearpygui.dearpygui as dpg
from datetime import datetime
import warnings

warnings.filterwarnings("ignore")  # Ignore joblib InconsistentVersionWarning

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

# Severity ranking for each packet.
ATTACK_SEVERITY = {
    "NORMAL": "0",
    "DOS": "3",
    "PROBE": "1",
    "R2L": "2",
    "U2R": "4",
    "SUSPICIOUS ACTIVITY": "Unavailable"
}


# Command Line Args Parser.
def get_args():
    parser = argparse.ArgumentParser("Arg parser for IDS.")
    parser.add_argument("-i", "--interface", default="gui", choices=["gui", "console"],
                        help="IDS interface [gui or console]")
    return parser.parse_args()


# GUI.
def ids_gui():

    dpg.create_context()
    dpg.create_viewport(title='IDS', width=200, height=200)

    with dpg.window(label='IDS Program'):
        dpg.add_text('Inject Packet:')
        dpg.add_button(label='NORMAL', tag='normal_btn', callback=lambda _: classify_packet(0))
        dpg.add_button(label='DOS', tag='dos_btn', callback=lambda _: classify_packet(1))
        dpg.add_button(label='PROBE', tag='probe_btn', callback=lambda _: classify_packet(2))
        dpg.add_button(label='U2R', tag='u2r_btn', callback=lambda _: classify_packet(3))
        dpg.add_button(label='R2L', tag='r2l_btn', callback=lambda _: classify_packet(4))

    dpg.setup_dearpygui()
    dpg.show_viewport()
    dpg.start_dearpygui()
    dpg.destroy_context()


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


def get_prediction(model, packet):
    """
    Gets prediction using specified model.
    :param model: MC or B model
    :param packet: unfiltered packet
    :return: prediction
    """
    if model == MC_MODEL:
        filtered_packet = packet[MC_FEATURES]  # Pre-process: Extract relevant features
    else:
        filtered_packet = packet[B_FEATURES]  # Pre-process: Extract relevant features
    filtered_packet_vals = filtered_packet.values
    prediction = model.predict(filtered_packet_vals)

    return prediction[0]


def prediction_logic(mc_prediction, b_prediction):
    """
    Makes a prediction based on the MC model and B model.
    :param mc_prediction: multi-class prediction
    :param b_prediction: binary class prediction
    :return: overall prediction
    """
    if mc_prediction != "NORMAL":
        return mc_prediction
    elif b_prediction != "NORMAL":
        return "SUSPICIOUS ACTIVITY"
    else:
        return "NORMAL"


def classify_packet(index):
    """
    Gets a random sample from the specified dataset and returns the prediction.
    :param index: 0: normal, 1: dos, 2: probe, 3: r2l, 4: u2r
    :return: prediction report
    """
    packet = SAMPLES[index].sample()  # Gets a random sample from the specified dataset

    mc_prediction = get_prediction(MC_MODEL, packet)
    b_prediction = get_prediction(B_MODEL, packet)

    result = prediction_logic(mc_prediction, b_prediction)

    return print(f"-----------------------------------------\n"
                 f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                 f"[*] Prediction: {result} \n"
                 f"[*] Severity: {ATTACK_SEVERITY[result]}")


# Load models
MC_MODEL = load('sp_rf_80.joblib')
B_MODEL = load('sp_rf_b_87.joblib')

# Load data samples and drop labels
SAMPLES = load_data_samples()
drop_labels(SAMPLES)


# Runs the program.
def main():
    args = get_args()

    if args.interface == "gui":  # GUI
        print('GUI mode.')
        ids_gui()
    else:  # Command Line Application
        print('Console app mode.')
        actions = ['1', '2', '3', '4', '5', '0']  # Valid actions
        while True:
            command = input('\nSelect type of packet or exit with [0]: \n'
                            '[1] Normal\n'
                            '[2] DOS\n'
                            '[3] PROBE\n'
                            '[4] U2R\n'
                            '[5] R2L\n\n'
                            'Selection: ')
            if command in actions:
                if command == '1':  # Normal packet
                    classify_packet(0)
                elif command == '2':  # Dos packet
                    classify_packet(1)
                elif command == '3':  # Probe packet
                    classify_packet(2)
                elif command == '4':  # U2R packet
                    classify_packet(3)
                elif command == '5':  # R2L packet
                    classify_packet(4)
                elif command == '0':  # Exit program
                    print('Exit...')
                    exit(1)
                continue
            else:
                print('Invalid Command. Try again.\n\n')
                continue


if __name__ == '__main__':
    main()
