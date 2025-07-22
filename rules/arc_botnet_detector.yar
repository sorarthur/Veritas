rule Detect_ARC_Botnet_Variant_C2
{
    meta:
        author = "Arthur Clemente Machado"
        date = "2025-07-21"
        description = "Detecta uma variante de botnet para arquitetura ARC baseada em um IP de C2 e strings de anti-competição."
        reference = "Análise do Ghidra" 
        hash_investigado = "49aecaef0747acb3bf5ea221c9959cadb1fce54b95efd8487d6440e4bf596222"

    strings:
        // Indicador de alta confiança: o IP do C2
        $ip_c2 = "196.251.72.205" wide ascii

        // Indicadores de competição/malware conhecidos.
        $s1 = "/tmp/condi" wide ascii
        $s2 = "/tmp/zxcr9999" wide ascii
        $s3 = "/var/condibot" wide ascii
        $s4 = "/var/CondiBot" wide ascii
        $s5 = "/var/condinet" wide ascii
        $s6 = "/var/zxcr9999" wide ascii

    condition:
        // 0x464c457f é a representação em hexadecimal para os caracteres ".ELF" no início de um arquivo.
        uint32(0) == 0x464c457f and (
            $ip_c2 or

            // "2 of ($s*)" em vez de "any of them" torna a regra mais robusta
            // e menos propensa a falsos positivos caso um desses nomes apareça
            // isoladamente em um arquivo legítimo por alguma coincidência.
            2 of ($s*)
        )
}