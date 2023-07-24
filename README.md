# Project15

## SM2 two-party sign签名方案简介

### 结构

签名

![image](https://github.com/1-14/Project15/blob/main/2.png)


### 原理

1.密钥生成：首先，两个参与者（通常称为Alice和Bob）各自生成自己的一对公钥和私钥。

2.初始参数交换：Alice选择一个随机数r1，Bob选择一个随机数r2，并将r1和r2交换。

3.签名数据准备：待签名的消息被哈希为一个固定长度的值，并与协商好的其他签名数据（如公钥、消息长度等）一起构成待签名数据。

4.签名计算：Alice使用自己的私钥和收到的r2，而Bob使用自己的私钥和收到的r1，两者进行一定的运算，最终得到两个部分的签名值。

5.签名合成：Alice和Bob交换各自计算得到的部分签名，然后结合这两个部分签名得到最终的数字签名。

6.签名验证：其他人可以使用Alice和Bob的公钥来验证这个合成的签名，确保消息的完整性和来源可信。

## 关键代码

### Alice

交换公钥：首先，Alice生成一个临时私钥d_1，并用其逆元生成一个临时公钥P_1，然后将P_1的横纵坐标发送给Bob。

签名：接下来，Alice和Bob共同完成签名过程。Alice发送待签名消息的hash值e，以及自己生成的临时公钥Q_1给Bob。Bob生成一个随机数k_1，然后用基点G进行点乘运算得到临时公钥Q_2，将Q_2的横纵坐标发送给Alice。然后，Bob通过私钥计算出签名的两个部分r和s_2，分别发送给Alice。

```
if __name__ == '__main__':
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 8000)
    server_socket.bind(server_address)

    server_socket.listen(1)
    print('Waiting for connecting...')

    client_socket, client_addr = server_socket.accept()
    print('Bob has connected!')

    #step1
    d_1 = random.randint(1, int_hex(n) - 1)
    d_1_inv = inv(d_1, int_hex(n))
    P_1 = mul_ECC(G, d_1_inv)
    client_socket.sendall(P_1[0].encode())
    client_socket.sendall(P_1[1].encode())

    #step2...

    #step3
    M = '6666'
    Z = '7777'
    M_ = M + Z
    e = sm3_hash(M_)

    k_1 = random.randint(1, int_hex(n) - 1)
    Q_1 = mul_ECC(G, k_1)
    client_socket.sendall(Q_1[0].encode())
    time.sleep(2)
    client_socket.sendall(Q_1[1].encode())
    time.sleep(2)
    client_socket.sendall(e.encode())

    #step4
    r = client_socket.recv(2048).decode()
    s_2 = client_socket.recv(2048).decode()
    s_3 = client_socket.recv(2048).decode()
    print(f'r, s_2, s_3: {r,s_2,s_3}')

    #step5
    tmp1 = (d_1 * k_1) * int_hex(s_2)
    tmp2 = d_1 * int_hex(s_3)
    s = (tmp1 + tmp2 - int_hex(r)) % int_hex(n)
    if s != 0 and s != int_hex(n) - int_hex(r):
        sigma = (r, hex(s)[2:])
        print(f'Sign result: {sigma}')
        
    client_socket.close()
    server_socket.close()
```

### Bob

交换公钥：Bob接收到Alice生成的临时公钥P_1，并用自己生成的临时私钥d_2进行点乘运算得到一个新的临时公钥P。然后，Bob将基点G的y坐标取负值，得到一个新的点G_inv，然后将P与G_inv进行点加运算，得到一个新的点P。

签名：Bob接收到Alice发送的待签名消息的hash值e，以及Alice生成的临时公钥Q_1。Bob生成两个随机数k_2和k_3，然后用基点G进行点乘运算得到两个临时公钥Q_2和Q_3，然后将Q_1与Q_2进行点加运算得到一个新的点(x_1, y_1)。
Bob根据公式计算签名的两个部分r和s_2，并通过r、s_2和临时私钥d_2计算出第三个签名部分s_3。最后，Bob将计算得到的r、s_2和s_3发送给Alice。

```
if __name__ == '__main__':
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 8000)

    print('Connecting to Alice...')

    try:
        client_socket.connect(server_address)
        print('Connect to Alice successfully!')
    except Exception:
        print('Failed to connect to Alice!')
        sys.exit()

    #step1
    x = client_socket.recv(2048).decode()
    y = client_socket.recv(2048).decode()
    P_1 = (x, y)
    print(f'P_1: {P_1}')

    #step2
    d_2 = random.randint(1, int_hex(n) - 1)
    d_2_inv = inv(d_2, int_hex(n))
    P = mul_ECC(P_1, d_2_inv)

    y_G_inv = hex(-int_hex(y_G))[3:]
    G_inv = (x_G, y_G_inv)
    P = add_ECC(P, G_inv)
    print(f'P: {P}')

    #step3
    x = client_socket.recv(2048).decode()
    y = client_socket.recv(2048).decode()
    e = client_socket.recv(2048).decode()
    Q_1 = (x, y)
    print(f'Q_1, e: {Q_1, e}')

    #step4
    k_2 = random.randint(1, int_hex(n) - 1)
    k_3 = random.randint(1, int_hex(n) - 1)

    Q_2 = mul_ECC(G, k_2)
    tmp = mul_ECC(Q_1, k_3)
    x_1, y_1 = add_ECC(tmp, Q_2)

    r = (int_hex(x_1) + int_hex(e)) % int_hex(n)
    s_2 = (d_2 * k_3) % int_hex(n)
    s_3 = (d_2 * (r + k_2)) % int_hex(n)

    r = hex(r)[2:]
    s_2 = hex(s_2)[2:]
    s_3 = hex(s_3)[2:]

    client_socket.sendall(r.encode())
    time.sleep(2)
    client_socket.sendall(s_2.encode())
    time.sleep(2)
    client_socket.sendall(s_3.encode())
    print(f'r, s_2, s_3: {r,s_2,s_3}')

    #step5...

    client_socket.close()
```

## 结果展示

左 Bob 右 Alice

![image](https://github.com/1-14/Project15/blob/main/1.png)



