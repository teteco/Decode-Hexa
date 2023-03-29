import binascii

def decode_ipv4_header(hex_header):
    try:
        raw_bytes = binascii.unhexlify(hex_header.replace(" ", ""))
    except binascii.Error:
        print("Erro: valor inválido em hexadecimal.")
        return

    # extrair informações do cabeçalho IP
    version = raw_bytes[0] >> 4
    header_length = raw_bytes[0] & 0x0F
    dscp = raw_bytes[1] >> 2
    ecn = raw_bytes[1] & 0x03
    total_length = int.from_bytes(raw_bytes[2:4], byteorder="big")
    identification = int.from_bytes(raw_bytes[4:6], byteorder="big")
    flags = (raw_bytes[6] >> 5) & 0x07
    fragment_offset = int.from_bytes(raw_bytes[6:8], byteorder="big") & 0x1FFF
    ttl = raw_bytes[8]
    protocol = raw_bytes[9]
    checksum = int.from_bytes(raw_bytes[10:12], byteorder="big")
    source_ip = ".".join(str(x) for x in raw_bytes[12:16])
    dest_ip = ".".join(str(x) for x in raw_bytes[16:20])

    # extrair informações do payload
    payload = raw_bytes[header_length*4:]

    # extrair informações do endereço MAC
    mac_source = hex_header[24:36]
    mac_dest = hex_header[12:24]

    # extrair informações das flags
    reserved_flag = (flags >> 2) & 0x01
    dont_fragment_flag = (flags >> 1) & 0x01
    more_fragment_flag = flags & 0x01

    # criar dicionário de protocolos conhecidos
    known_protocols = {1: "ICMP", 6: "TCP", 17: "UDP"}

    # obter o nome do protocolo, se conhecido
    protocol_name = known_protocols.get(protocol, "desconhecido")

    # formatar e imprimir informações
    print(f"Endereço MAC de origem:    {':'.join(mac_source[i:i+2] for i in range(0, len(mac_source), 2))}")
    print(f"Endereço MAC de destino:  {':'.join(mac_dest[i:i+2] for i in range(0, len(mac_dest), 2))}")
    print(f"Endereço IP de origem:    {source_ip}")
    print(f"Endereço IP de destino:   {dest_ip}")
    print(f"Comprimento total:        {total_length}")
    print(f"Identificação:            {identification}")
    print(f"Flags:                    reservado={reserved_flag} não fragmentar={dont_fragment_flag} mais fragmentos={more_fragment_flag}")
    print(f"Deslocamento de fragmento: {fragment_offset}")
    print(f"TTL:                      {ttl}")
    print(f"Protocolo:                {protocol_name} ({protocol})")
    print(f"Checksum:                 {checksum}")
    print(f"Tipo de serviço:          {dscp}")
    print(f"Comprimento do cabeçalho IP: {header_length*4}")
    print(f"Payload:                  {payload}")

def main():
    hex_header = input("Digite o valor em hexadecimal: ")
    decoded_header = decode_ipv4_header(hex_header)

if __name__ == "__main__":
    main()
