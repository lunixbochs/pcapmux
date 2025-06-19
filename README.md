pcapmux
---

## usage

    # ssh mode
    pcapmux ssh host1 host2 -- tcpdump -U -w - | wireshark -k -i -

    # local command mode
    pcapmux run 'tcpdump -i en0 -U -w -' 'tcpdump -i en1 -U -w -' | wireshark -k -i -
