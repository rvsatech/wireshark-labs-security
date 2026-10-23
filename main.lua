-- ============================================================================
-- Script: security_hunter.lua
-- Objetivo: Identificar tráfego HTTP inseguro e potenciais varreduras de portas (Port Scanning)
-- Contexto: Threat Hunting / Auditoria de Redes
-- ============================================================================

local http_count = 0
local port_scan_log = {}
local port_scan_threshold = 10 -- Alerta se um IP tentar acessar mais de 10 portas diferentes

-- 1. Listener para tráfego HTTP (Inseguro)
local http_listener = Listener.new("ip", "http")

function http_listener.packet(pinfo, tvb, ip)
    http_count = http_count + 1
end

-- 2. Listener para conexões TCP (Detectar varredura de portas)
local tcp_listener = Listener.new("ip", "tcp.flags.syn == 1 and tcp.flags.ack == 0")

function tcp_listener.packet(pinfo, tvb, ip)
    local src_ip = tostring(pinfo.src)
    local dst_port = tostring(pinfo.dst_port)

    if not port_scan_log[src_ip] then
        port_scan_log[src_ip] = {}
    end
    
    -- Registra a porta única que o IP tentou acessar
    port_scan_log[src_ip][dst_port] = true
end

-- 3. Função que consolida o relatório final de segurança
function tcp_listener.draw()
    print("\n" .. string.rep("=", 60))
    print("      RELATÓRIO DE AUDITORIA DE SEGURANÇA (WIRESHARK LUA)      ")
    print(string.rep("=", 60))

    -- Alerta de Tráfego Inseguro
    print(string.format("[*] Análise de Protocolos Inseguros:"))
    if http_count > 0 then
        print(string.format("    ⚠️ ALERTA: Detectados %d pacotes HTTP sem criptografia!", http_count))
    else
        print("    ✅ Nenhum tráfego HTTP sem criptografia detectado.")
    end
    print(string.rep("-", 60))

    -- Alerta de Port Scanning
    print("[*] Análise de Varredura de Portas (Port Scanning):")
    local varredura_detectada = false
    
    for ip, portas in pairs(port_scan_log) do
        local total_portas = 0
        for _ in pairs(portas) do total_portas = total_portas + 1 end
        
        if total_portas >= port_scan_threshold then
            print(string.format("    🚨 SUSPEITO: O IP %s tentou conectar em %d portas diferentes!", ip, total_portas))
            varredura_detectada = true
        end
    end
    
    if not varredura_detectada then
        print("    ✅ Nenhuma atividade suspeita de Port Scanning encontrada.")
    end
    print(string.rep("=", 60) .. "\n")
end

-- Força o Wireshark a reprocessar os pacotes aplicando as regras acima
retap_packets()
