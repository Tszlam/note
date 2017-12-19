let net = require('net');
let crypto = require('crypto');
let ws_key = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

let socketList = [];

let server = net.createServer(function (socket) {
    let key;
    let connectionState = 0;
    socketList.push({
        name: '',
        socket: socket
    });

    socket.on('data', function (e) {
        if (!key) {
            //握手
            key = e.toString().match(/Sec-WebSocket-Key: (.+)/)[1];
            key = crypto.createHash('sha1').update(key + ws_key).digest('base64');
            socket.write('HTTP/1.1 101 Switching Protocols\r\n');
            socket.write('Upgrade: websocket\r\n');
            socket.write('Connection: Upgrade\r\n');
            socket.write('Sec-WebSocket-Accept: ' + key + '\r\n');
            socket.write('\r\n');
        } else {
            //数据传输
            //解包
            let data = decodeDataFrame(e);
            //判断是否要断开链接
            if (data.Opcode == 8) {
                socket.end();
                return;
            }
            //解析数据
            let payLoad = JSON.parse(data.PayloadData.toString());
            //写用户名
            if (payLoad.name) {
                socket.name = payLoad.name;
                socketList.forEach((_socket, idx) => {
                    if (_socket.socket != socket && _socket.socket != null) {
                        _socket.socket.write(packData(`【系统】：${socket.name} 加入会话`));
                    }
                });
                return;
            }
            //发信息
            if (payLoad.msg) {
                socketList.forEach((_socket, idx) => {
                    if (_socket.socket != socket && _socket.socket != null) {
                        _socket.socket.write(packData(`【${socket.name}】：${payLoad.msg}`));
                    }
                });
            }
        };
    });

    socket.on('end', () => {
        //有人退出时通知其他人
        let skIdx;
        socketList.forEach((_socket, idx) => {
            if (_socket.socket == socket) skIdx = idx;
            if (_socket.socket != socket && _socket.socket != null) {
                _socket.socket.write(packData(`【系统】：${socket.name} 已退出会话`))
            }
        })
        socketList.splice(skIdx, 1);
    });
});
//监听8000端口
server.listen(8000);


function packData(data) {
    let pkg = {
        FINISH: 1,
        Opcode: 1,
        PayloadData: data
    }
    return encodeDataFrame(pkg);
}
function decodeDataFrame(e) {
    var i = 0, j, s, frame = {
        //解析前两个字节的基本数据
        FINISH: e[i] >> 7,
        Opcode: e[i++] & 15,
        Mask: e[i] >> 7,
        PayloadLength: e[i++] & 0x7F
    };
    //处理特殊长度126和127
    if (frame.PayloadLength == 126)
        frame.length = (e[i++] << 8) + e[i++];
    if (frame.PayloadLength == 127)
        i += 4, //长度一般用四字节的整型，前四个字节通常为长整形留空的
            frame.length = (e[i++] << 24) + (e[i++] << 16) + (e[i++] << 8) + e[i++];
    //判断是否使用掩码
    if (frame.Mask) {
        //获取掩码实体
        frame.MaskingKey = [e[i++], e[i++], e[i++], e[i++]];
        //对数据和掩码做异或运算
        for (j = 0, s = []; j < frame.PayloadLength; j++)
            s.push(e[i + j] ^ frame.MaskingKey[j % 4]);
    } else s = e.slice(i, frame.PayloadLength); //否则直接使用数据
    //数组转换成缓冲区来使用
    s = new Buffer(s);
    //如果有必要则把缓冲区转换成字符串来使用
    if (frame.Opcode == 1) s = s.toString();
    //设置上数据部分
    frame.PayloadData = s;
    //返回数据帧
    return frame;
}
function encodeDataFrame(e) {
    var s = [], o = new Buffer(e.PayloadData), l = o.length;
    //输入第一个字节
    s.push((e.FINISH << 7) + e.Opcode);
    //输入第二个字节，判断它的长度并放入相应的后续长度消息
    //永远不使用掩码
    if (l < 126) s.push(l);
    else if (l < 0x10000) s.push(126, (l & 0xFF00) >> 2, l & 0xFF);
    else s.push(
        127, 0, 0, 0, 0, //8字节数据，前4字节一般没用留空
        (l & 0xFF000000) >> 6, (l & 0xFF0000) >> 4, (l & 0xFF00) >> 2, l & 0xFF
    );
    //返回头部分和数据部分的合并缓冲区
    return Buffer.concat([new Buffer(s), o]);
}