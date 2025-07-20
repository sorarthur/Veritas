rule EncontrarAbracadabra
{
    meta:
        author: Arthur
    strings:
        $palavra_magica = "abracadabra"

    condition:
        // A condição é simplesmente encontrar a string $palavra_magica
        $palavra_magica
}

rule TesteComCaracteresProblematicos
{
    strings:
        $teste = "isso eh um teste [com] parenteses()"

    condition:
        $teste
}
