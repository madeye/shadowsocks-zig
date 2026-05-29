#!/usr/bin/env python3
import os
import socket
import threading


def pipe(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for sock in (src, dst):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass


def handle(client, target):
    try:
        upstream = socket.create_connection(target, timeout=10)
    except OSError:
        client.close()
        return
    threading.Thread(target=pipe, args=(client, upstream), daemon=True).start()
    threading.Thread(target=pipe, args=(upstream, client), daemon=True).start()


def tcp_loop(listen_addr, target_addr):
    listener = socket.socket(socket.AF_INET6 if ":" in listen_addr[0] else socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(listen_addr)
    listener.listen(128)

    while True:
        client, _ = listener.accept()
        threading.Thread(target=handle, args=(client, target_addr), daemon=True).start()


def udp_loop(listen_addr, target_addr):
    sock = socket.socket(socket.AF_INET6 if ":" in listen_addr[0] else socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(listen_addr)
    peer_for_target = {}
    target_for_peer = {}

    while True:
        data, peer = sock.recvfrom(65536)
        if peer == target_addr:
            client = peer_for_target.get(peer)
            if client is not None:
                sock.sendto(data, client)
        else:
            peer_for_target[target_addr] = peer
            target_for_peer[peer] = target_addr
            sock.sendto(data, target_for_peer[peer])


def main():
    remote = (os.environ["SS_REMOTE_HOST"], int(os.environ["SS_REMOTE_PORT"]))
    local = (os.environ["SS_LOCAL_HOST"], int(os.environ["SS_LOCAL_PORT"]))
    opts = os.environ.get("SS_PLUGIN_OPTIONS", "")

    listen_addr, target_addr = (remote, local) if "server" in opts.split(";") else (local, remote)
    threading.Thread(target=udp_loop, args=(listen_addr, target_addr), daemon=True).start()
    tcp_loop(listen_addr, target_addr)


if __name__ == "__main__":
    main()
