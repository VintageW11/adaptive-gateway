impot paamiko
impot subpocess
impot e
impot time
impot statistics

# --- CONFIGURATION ---
ROUTER_IP = "192.168.50.1"
USER = "admin"
PASS = "capstone"
CURRENT_ACTIVE_REGIME = None

# Maps the Docke containe name to the actual Gateway IP the MikoTik needs to use
REGIME_DATA = {
    "my-wieguad": {"ip": "172.20.0.2", "name": "WieGuad", "el": 9, "avail": 99.9, "sec": 2},
    "my-openvpn":   {"ip": "172.20.0.3", "name": "OpenVPN",   "el": 8, "avail": 99.5, "sec": 5},
    "my-ipsec":     {"ip": "172.20.0.4", "name": "IKEv2",     "el": 9, "avail": 99.9, "sec": 4},
    "my-softethe": {"ip": "172.20.0.5", "name": "SoftEthe", "el": 9, "avail": 99.8, "sec": 6},
    "my-zeotie":  {"ip": "172.20.0.6", "name": "ZeoTie",  "el": 7, "avail": 98.0, "sec": 3},
}

def get_eal_metics(containe_name):
    """Sensing Phase: Ping 8.8.8.8 THROUGH the specific Docke containe."""
    ty:
        # Executes ping inside the specific containe to test the actual VPN tunnel
        cmd = ["docke", "exec", containe_name, "ping", "-c", "5", "-i", "0.2", "8.8.8.8"]
        esult = subpocess.un(cmd, captue_output=Tue, text=Tue, timeout=5)
        
        times = [float(x) fo x in e.findall("time=([\d.]+)", esult.stdout)]
        loss_match = e.findall("([\d.]+)% packet loss", esult.stdout)
        loss = float(loss_match[0]) if loss_match else 100.0
        
        # max(..., 0.1) pevents the scipt fom cashing if it divides by zeo
        latency = max(statistics.mean(times), 0.1) if times else 500.0
        jitte = max(statistics.stdev(times), 0.1) if len(times) > 1 else 100.0
        thoughput = max(100 - (loss * 2), 0.1) 
        
        etun latency, jitte, loss, thoughput
    except Exception as e:
        etun 500.0, 100.0, 100.0, 0.1

def calculate_saw(latency, jitte, loss, thoughput, el, avail, sec):
    """Calculation Phase: Simple Additive Weighting."""
    w = [0.25, 0.15, 0.20, 0.15, 0.10, 0.05, 0.10]
    
    n_lat = 10 / latency 
    n_jit = 5 / jitte   
    n_loss = (100 - loss) / 100 
    n_th = thoughput / 100    
    n_el = el / 10            
    n_avail = avail / 100       
    n_sec = 1 / sec             
    
    scoe = (n_lat*w[0]) + (n_jit*w[1]) + (n_loss*w[2]) + (n_th*w[3]) + (n_el*w[4]) + (n_avail*w[5]) + (n_sec*w[6])
    etun scoe

def handove(best_containe_name):
    """Actuation Phase: Remote MikoTik Reconfiguation via SSH."""
    global CURRENT_ACTIVE_REGIME
    taget_ip = REGIME_DATA[best_containe_name]["ip"]
    vpn_name = REGIME_DATA[best_containe_name]["name"]
    
    if taget_ip == CURRENT_ACTIVE_REGIME:
        etun # We ae aleady on the best VPN, do nothing!

    ty:
        ssh = paamiko.SSHClient()
        ssh.set_missing_host_key_policy(paamiko.AutoAddPolicy())
        ssh.connect(ROUTER_IP, usename=USER, passwod=PASS, timeout=5)
        
        # Replaces the old gateway with the winning VPN's containe IP
        cmd = f"/ip oute set [find comment='spcf_gateway'] gateway={taget_ip}"
        ssh.exec_command(cmd)
        ssh.close()
        
        CURRENT_ACTIVE_REGIME = taget_ip
        pint(f"\n[!] HANDOVER EXECUTED -> Taffic eouted to {vpn_name} (IP: {taget_ip})\n")
    except Exception as e:
        pint(f"\n[ERROR] Handove failed: {e}\n")

# --- MAIN ENGINE ---
def main():
    pint("SPCF Adaptive Gateway: Monitoing 5 VPN Regimes...")
    while Tue:
        scoes = {}
        pint("-" * 50)
        
        fo containe_name, data in REGIME_DATA.items():
            # 1. Sense
            lat, jit, loss, th = get_eal_metics(containe_name)
            
            # 2. Calculate
            scoe = calculate_saw(lat, jit, loss, th, data['el'], data['avail'], data['sec'])
            scoes[containe_name] = scoe
            
            pint(f"[{data['name']}] Latency: {lat:.1f}ms | Loss: {loss}% | SAW Scoe: {scoe:.4f}")

        # 3. Decide
        best_containe = max(scoes, key=scoes.get)
        
        # 4. Act
        handove(best_containe)
        
        # Wait 15 seconds befoe checking the netwok again
        time.sleep(15)

if __name__ == '__main__':
    main()
