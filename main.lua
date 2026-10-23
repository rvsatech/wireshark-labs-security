local http_count = 0
local port_scan_log = {}
local port_scan_threshold = 10

-- Remove os listeners de um dofile anterior (evita duplicados)
if _G.sh_listeners then
    for _, l in ipairs(_G.sh_listeners) do l:remove() end
end

-- tap nil = "frame": recebe IPv4 E IPv6; quem filtra é o 2º argumento
local http_listener = Listener.new(nil, "http")
local tcp_listener  = Listener.new(nil, "tcp.flags.syn == 1 and tcp.flags.ack == 0")
_G.sh_listeners = { http_listener, tcp_listener }

function http_listener.packet(pinfo, tvb)
    http_count = http_count + 1
end
function http_listener.reset()          -- chamado antes de cada retap
    http_count = 0
end

function tcp_listener.packet(pinfo, tvb)
    local src_ip   = tostring(pinfo.src)
    local dst_port = tostring(pinfo.dst_port)
    port_scan_log[src_ip] = port_scan_log[src_ip] or {}
    port_scan_log[src_ip][dst_port] = true
end
function tcp_listener.reset()
    port_scan_log = {}
end

-- Relatório como função GLOBAL: você chama quando quiser no console
function relatorio()
    print("\n" .. string.rep("=", 60))
    print("      RELATÓRIO DE AUDITORIA DE SEGURANÇA (WIRESHARK LUA)")
    print(string.rep("=", 60))

    print("[*] Análise de Protocolos Inseguros:")
    if http_count > 0 then
        print(string.format("    ⚠️ ALERTA: %d pacotes HTTP sem criptografia!", http_count))
    else
        print("    ✅ Nenhum tráfego HTTP sem criptografia detectado.")
    end
    print(string.rep("-", 60))

    print("[*] Análise de Varredura de Portas:")
    local achou = false
    for ip, portas in pairs(port_scan_log) do
        local total = 0
        for _ in pairs(portas) do total = total + 1 end
        if total >= port_scan_threshold then
            print(string.format("    🚨 SUSPEITO: %s tentou %d portas diferentes!", ip, total))
            achou = true
        end
    end
    if not achou then
        print("    ✅ Nenhuma atividade suspeita de Port Scanning.")
    end
    print(string.rep("=", 60) .. "\n")
end

retap_packets()