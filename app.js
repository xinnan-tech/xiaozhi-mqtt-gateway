// Description: MQTT+UDP 到 WebSocket 的桥接
// Author: terrence@tenclass.com
// Date: 2025-03-12

require('dotenv').config();
const net = require('net');
const debugModule = require('debug');
const debug = debugModule('mqtt-server');
const crypto = require('crypto');
const dgram = require('dgram');
const Emitter = require('events');
const WebSocket = require('ws');
const { MQTTProtocol } = require('./mqtt-protocol');
const { ConfigManager } = require('./utils/config-manager');
const { validateMqttCredentials } = require('./utils/mqtt_config_v2');


function setDebugEnabled(enabled) {
    if (enabled) {
        debugModule.enable('mqtt-server');
    } else {
        debugModule.disable();
    }
}

const configManager = new ConfigManager('mqtt.json');
configManager.on('configChanged', (config) => {
    setDebugEnabled(config.debug);
});

setDebugEnabled(configManager.get('debug'));

class WebSocketBridge extends Emitter {
    constructor(connection, protocolVersion, macAddress, uuid, userData) {
        super();
        this.connection = connection;
        this.macAddress = macAddress;
        this.uuid = uuid;
        this.userData = userData;
        this.wsClient = null;
        this.protocolVersion = protocolVersion;
        this.deviceSaidGoodbye = false;
        this.initializeChatServer();
    }

    initializeChatServer() {
        const devMacAddresss = configManager.get('development')?.mac_addresss || [];
        let chatServers;
        if (devMacAddresss.includes(this.macAddress)) {
            chatServers = configManager.get('development')?.chat_servers;
        } else {
            chatServers = configManager.get('production')?.chat_servers;
        }
        if (!chatServers) {
            throw new Error(`未找到 ${this.macAddress} 的聊天服务器`);
        }
        this.chatServer = chatServers[Math.floor(Math.random() * chatServers.length)];
    }

    async connect(audio_params, features) {
        return new Promise((resolve, reject) => {
            // 生成WebSocket认证token
            let authorization = "test-token";
            const serverSecret = process.env.SERVER_SECRET;
            if (serverSecret) {
                const clientId = this.uuid || 'default-client-id';
                const username = this.macAddress;
                const timestamp = Math.floor(Date.now() / 1000);

                // 构建签名内容: clientId|username|timestamp
                const content = `${clientId}|${username}|${timestamp}`;

                // 生成HMAC-SHA256签名
                const hmac = crypto.createHmac('sha256', serverSecret);
                hmac.update(content);
                const signature = hmac.digest();

                // Base64 URL-safe编码签名(去除填充符=)
                const signatureBase64 = signature.toString('base64url');

                // 生成认证token: signature.timestamp
                authorization = `${signatureBase64}.${timestamp}`;
            }

            const headers = {
                'device-id': this.macAddress,
                'protocol-version': '2',
                'authorization': `Bearer ${authorization}`
            };
            if (this.uuid) {
                headers['client-id'] = this.uuid;
            }
            if (this.userData && this.userData.ip) {
                headers['x-forwarded-for'] = this.userData.ip;
            }
            this.wsClient = new WebSocket(this.chatServer, { headers });

            this.wsClient.on('open', () => {
                this.sendJson({
                    type: 'hello',
                    version: 2,
                    transport: 'websocket',
                    audio_params,
                    features
                });
            });

            this.wsClient.on('message', (data, isBinary) => {
                if (isBinary) {
                    const timestamp = data.readUInt32BE(8);
                    const opusLength = data.readUInt32BE(12);
                    const opus = data.subarray(16, 16 + opusLength);
                    // 二进制数据通过UDP发送
                    this.connection.sendUdpMessage(opus, timestamp);
                } else {
                    // JSON数据通过MQTT发送
                    const message = JSON.parse(data.toString());
                    if (message.type === 'hello') {
                        resolve(message);
                    } else if (message.type === 'mcp' &&
                        this.connection.mcpCachedTools &&
                        ['notifications/initialized', 'tools/list'].includes(message.payload.method)) {
                        this.connection.onMcpMessageFromBridge(message);
                    } else {
                        this.connection.sendMqttMessage(JSON.stringify(message));
                    }
                }
            });

            this.wsClient.on('error', (error) => {
                console.error(`WebSocket error for device ${this.macAddress}:`, error);
                this.emit('close');
                reject(error);
            });

            this.wsClient.on('close', () => {
                this.emit('close');
            });
        });
    }

    sendJson(message) {
        if (this.wsClient && this.wsClient.readyState === WebSocket.OPEN) {
            this.wsClient.send(JSON.stringify(message));
        }
    }

    sendAudio(opus, timestamp) {
        if (this.wsClient && this.wsClient.readyState === WebSocket.OPEN) {
            const buffer = Buffer.alloc(16 + opus.length);
            buffer.writeUInt32BE(timestamp, 8);
            buffer.writeUInt32BE(opus.length, 12);
            buffer.set(opus, 16);
            this.wsClient.send(buffer, { binary: true });
        } else {
            console.error(`WebSocket连接不可用，无法发送音频数据`);
        }
    }

    isAlive() {
        return this.wsClient && this.wsClient.readyState === WebSocket.OPEN;
    }

    close() {
        if (this.wsClient) {
            this.wsClient.close();
            this.wsClient = null;
        }
    }
}

const MacAddressRegex = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/;

/**
 * MQTT连接类
 * 负责应用层逻辑处理
 */
class MQTTConnection {
    constructor(socket, connectionId, server) {
        this.server = server;
        this.connectionId = connectionId;
        this.clientId = null;
        this.username = null;
        this.password = null;
        this.bridge = null;
        this.udp = {
            remoteAddress: null,
            cookie: null,
            localSequence: 0,
            remoteSequence: 0
        };
        this.headerBuffer = Buffer.alloc(16);
        this.mcpPendingRequests = {};

        // 提取真实的客户端IP
        this.realClientIp = socket.remoteAddress;

        // 创建协议处理器，并传入socket
        this.protocol = new MQTTProtocol(socket, configManager);

        this.setupProtocolHandlers();
    }

    setupProtocolHandlers() {
        // 设置协议事件处理
        this.protocol.on('connect', (connectData) => {
            this.handleConnect(connectData);
        });

        this.protocol.on('publish', (publishData) => {
            this.handlePublish(publishData);
        });

        this.protocol.on('subscribe', (subscribeData) => {
            this.handleSubscribe(subscribeData);
        });

        this.protocol.on('disconnect', () => {
            this.handleDisconnect();
        });

        this.protocol.on('close', () => {
            debug(`${this.clientId} 客户端断开连接`);
            this.server.removeConnection(this);
        });

        this.protocol.on('error', (err) => {
            debug(`${this.clientId} 连接错误:`, err);
            this.close();
        });

        this.protocol.on('protocolError', (err) => {
            debug(`${this.clientId} 协议错误:`, err);
            this.close();
        });
    }

    handleConnect(connectData) {
        this.clientId = connectData.clientId;
        this.username = connectData.username;
        this.password = connectData.password;

        debug('客户端连接:', {
            clientId: this.clientId,
            username: this.username,
            password: this.password,
            protocol: connectData.protocol,
            protocolLevel: connectData.protocolLevel,
            keepAlive: connectData.keepAlive
        });

        const parts = this.clientId.split('@@@');
        if (parts.length === 3) { // GID_test@@@mac_address@@@uuid
            const validated = validateMqttCredentials(this.clientId, this.username, this.password, this.realClientIp);
            this.groupId = validated.groupId;
            this.macAddress = validated.macAddress;
            this.uuid = validated.uuid;
            this.userData = validated.userData;
        } else if (parts.length === 2) { // GID_test@@@mac_address
            this.groupId = parts[0];
            this.macAddress = parts[1].replace(/_/g, ':');
            if (!MacAddressRegex.test(this.macAddress)) {
                debug('无效的 macAddress:', this.macAddress);
                this.close();
                return;
            }
        } else {
            debug('无效的 clientId:', this.clientId);
            this.close();
            return;
        }
        this.replyTo = `devices/p2p/${parts[1]}`;

        this.server.addConnection(this);
        this.initializeDeviceTools();
    }

    handleSubscribe(subscribeData) {
        debug('客户端订阅主题:', {
            clientId: this.clientId,
            topic: subscribeData.topic,
            packetId: subscribeData.packetId
        });

        // 发送 SUBACK
        this.protocol.sendSuback(subscribeData.packetId, 0);
    }

    handleDisconnect() {
        debug('收到断开连接请求:', { clientId: this.clientId });
        // 清理连接
        this.server.removeConnection(this);
    }

    close() {
        this.closing = true;
        // 清理所有未完成的 MCP 请求
        for (const request of Object.values(this.mcpPendingRequests)) {
            request.reject(new Error('Connection closed'));
        }
        this.mcpPendingRequests = {};

        if (this.bridge) {
            this.bridge.close();
            this.bridge = null;
        } else {
            this.protocol.close();
        }
    }

    checkKeepAlive() {
        const now = Date.now();
        const keepAliveInterval = this.protocol.getKeepAliveInterval();

        // 如果keepAliveInterval为0，表示不需要心跳检查
        if (keepAliveInterval === 0 || !this.protocol.isConnected) return;

        const lastActivity = this.protocol.getLastActivity();
        const timeSinceLastActivity = now - lastActivity;

        // 如果超过心跳间隔，关闭连接
        if (timeSinceLastActivity > keepAliveInterval) {
            debug('心跳超时，关闭连接:', this.clientId);
            this.close();
        }
    }

    handlePublish(publishData) {
        debug('收到发布消息:', {
            clientId: this.clientId,
            topic: publishData.topic,
            payload: publishData.payload,
            qos: publishData.qos
        });

        if (publishData.qos !== 0) {
            debug('不支持的 QoS 级别:', publishData.qos, '关闭连接');
            this.close();
            return;
        }

        const json = JSON.parse(publishData.payload);
        if (json.type === 'hello') {
            if (json.version !== 3) {
                debug('不支持的协议版本:', json.version, '关闭连接');
                this.close();
                return;
            }
            this.parseHelloMessage(json).catch(error => {
                debug('处理 hello 消息失败:', error);
                this.close();
            });
        } else {
            this.parseOtherMessage(json).catch(error => {
                debug('处理其他消息失败:', error);
                this.close();
            });
        }
    }

    sendMqttMessage(payload) {
        debug(`发送消息到 ${this.replyTo}: ${payload}`);
        this.protocol.sendPublish(this.replyTo, payload, 0, false, false);
    }

    sendUdpMessage(payload, timestamp) {
        if (!this.udp.remoteAddress) {
            debug(`设备 ${this.clientId} 未连接，无法发送 UDP 消息`);
            return;
        }
        this.udp.localSequence++;
        const header = this.generateUdpHeader(payload.length, timestamp, this.udp.localSequence);
        const cipher = crypto.createCipheriv(this.udp.encryption, this.udp.key, header);
        const message = Buffer.concat([header, cipher.update(payload), cipher.final()]);
        this.server.sendUdpMessage(message, this.udp.remoteAddress);
    }

    generateUdpHeader(length, timestamp, sequence) {
        // 重用预分配的缓冲区
        this.headerBuffer.writeUInt8(1, 0);
        this.headerBuffer.writeUInt16BE(length, 2);
        this.headerBuffer.writeUInt32BE(this.connectionId, 4);
        this.headerBuffer.writeUInt32BE(timestamp, 8);
        this.headerBuffer.writeUInt32BE(sequence, 12);
        return Buffer.from(this.headerBuffer); // 返回副本以避免并发问题
    }

    async parseHelloMessage(json) {
        this.udp = {
            ...this.udp,
            key: crypto.randomBytes(16),
            nonce: this.generateUdpHeader(0, 0, 0),
            encryption: 'aes-128-ctr',
            remoteSequence: 0,
            localSequence: 0,
            startTime: Date.now()
        }

        if (this.bridge) {
            debug(`${this.clientId} 收到重复 hello 消息，关闭之前的 bridge`);
            this.bridge.close();
            await new Promise(resolve => setTimeout(resolve, 100));
        }
        this.bridge = new WebSocketBridge(this, json.version, this.macAddress, this.uuid, this.userData);
        this.bridge.on('close', () => {
            const seconds = (Date.now() - this.udp.startTime) / 1000;
            console.log(`通话结束: ${this.clientId} Session: ${this.udp.session_id} Duration: ${seconds}s`);
            this.sendMqttMessage(JSON.stringify({ type: 'goodbye', session_id: this.udp.session_id }));
            this.bridge = null;
            if (this.closing) {
                this.protocol.close();
            }
        });

        try {
            console.log(`通话开始: ${this.clientId} Protocol: ${json.version} ${this.bridge.chatServer}`);
            const helloReply = await this.bridge.connect(json.audio_params, json.features);
            this.udp.session_id = helloReply.session_id;
            this.sendMqttMessage(JSON.stringify({
                type: 'hello',
                version: json.version,
                session_id: this.udp.session_id,
                transport: 'udp',
                udp: {
                    server: this.server.publicIp,
                    port: this.server.udpPort,
                    encryption: this.udp.encryption,
                    key: this.udp.key.toString('hex'),
                    nonce: this.udp.nonce.toString('hex'),
                },
                audio_params: helloReply.audio_params
            }));
        } catch (error) {
            this.sendMqttMessage(JSON.stringify({ type: 'error', message: '处理 hello 消息失败' }));
            console.error(`${this.clientId} 处理 hello 消息失败: ${error}`);
        }
    }

    async parseOtherMessage(json) {
        if (json.type === 'mcp') {
            const { id, error, result } = json.payload;
            const request = this.mcpPendingRequests[id];
            if (request) {
                delete this.mcpPendingRequests[id];
                if (error) {
                    request.reject(new Error(error.message));
                } else {
                    request.resolve(result);
                }
                return;
            }
        }

        if (!this.bridge) {
            if (json.type !== 'goodbye') {
                this.sendMqttMessage(JSON.stringify({ type: 'goodbye', session_id: json.session_id }));
            }
            return;
        }

        if (json.type === 'goodbye') {
            this.bridge.close();
            this.bridge = null;
            return;
        }

        this.bridge.sendJson(json);
    }

    onUdpMessage(rinfo, message, payloadLength, timestamp, sequence) {
        if (!this.bridge) {
            return;
        }
        if (this.udp.remoteAddress !== rinfo) {
            this.udp.remoteAddress = rinfo;
            // 初始化音频时间戳基准
            this.udp.audioStartTime = Date.now();
            this.udp.audioSequenceStart = sequence;
            this.udp.remoteSequence = sequence - 1; // 设置为当前序列号-1，这样下次检查会通过
        }
        if (sequence < this.udp.remoteSequence) {
            return;
        }
        if (sequence !== this.udp.remoteSequence + 1) {
            console.warn(`Received audio packet with wrong sequence: ${sequence}, expected: ${this.udp.remoteSequence + 1}`, {
                remoteAddress: rinfo.address,
                remotePort: rinfo.port,
                clientId: this.clientId
            });
        }

        // 由于设备发送的时间戳为0，我们根据序列号生成时间戳
        // 假设每个音频包60ms (Opus帧时长)，使用32位时间戳
        const frameMs = 60;
        const relativeTimeMs = (sequence - this.udp.audioSequenceStart) * frameMs;
        // 使用相对时间戳，避免超出32位范围
        const correctedTimestamp = (relativeTimeMs) % (2 ** 32);

        console.log(`收到UDP音频数据从 ${this.clientId}, 长度: ${payloadLength}, 原时间戳: ${timestamp}, 修正时间戳: ${correctedTimestamp}, 序列号: ${sequence}`);

        // 处理加密数据
        const header = message.slice(0, 16);
        const encryptedPayload = message.slice(16, 16 + payloadLength);

        // 添加解密错误处理
        try {
            const cipher = crypto.createDecipheriv(this.udp.encryption, this.udp.key, header);
            const payload = Buffer.concat([cipher.update(encryptedPayload), cipher.final()]);

            console.log(`UDP音频解密成功，转发到WebSocket，opus长度: ${payload.length}`);
            // 使用修正后的时间戳
            this.bridge.sendAudio(payload, correctedTimestamp);
            this.udp.remoteSequence = sequence;
        } catch (decryptionError) {
            console.error(`UDP 解密失败: ${decryptionError.message}`, {
                sequence: sequence,
                expectedSequence: this.udp.remoteSequence + 1,
                payloadLength: payloadLength,
                remoteAddress: rinfo.address,
                remotePort: rinfo.port
            });
            return;
        }
    }

    isAlive() {
        return this.bridge && this.bridge.isAlive();
    }

    // Cache device tools to MQTTConnection
    async initializeDeviceTools() {
        this.mcpRequestId = 10000;
        this.mcpPendingRequests = {};
        this.mcpCachedTools = [];

        try {
            const mcpClient = configManager.get('mcp_client') || {};
            const capabilities = mcpClient.capabilities || {};
            const clientInfo = mcpClient.client_info || {
                name: 'xiaozhi-mqtt-client',
                version: '1.0.0'
            };
            this.mcpCachedInitialize = await this.sendMcpRequest('initialize', {
                protocolVersion: '2024-11-05',
                capabilities,
                clientInfo
            });
            this.sendMqttMessage(JSON.stringify({
                type: 'mcp',
                payload: { jsonrpc: '2.0', method: 'notifications/initialized' }
            }));

            // list tools
            let cursor = undefined;
            const maxToolsCount = configManager.get('mcp_client.max_tools_count') || 32;
            do {
                const { tools, nextCursor } = await this.sendMcpRequest('tools/list', { cursor });
                if (tools.length === 0 || (this.mcpCachedTools.length + tools.length) > maxToolsCount) {
                    break;
                }
                this.mcpCachedTools = this.mcpCachedTools.concat(tools);
                cursor = nextCursor;
            } while (cursor !== undefined);
            debug('初始化设备工具成功:', this.mcpCachedTools);
        } catch (error) {
            debug("Error initializing device tools", error);
        }
    }

    sendMcpRequest(method, params, timeout = 10000) {
        const id = this.mcpRequestId++;
        return new Promise((resolve, reject) => {
            // 设置超时定时器
            const timer = setTimeout(() => {
                if (this.mcpPendingRequests[id]) {
                    delete this.mcpPendingRequests[id];
                    reject(new Error('timeout'));
                }
            }, timeout);

            this.mcpPendingRequests[id] = {
                resolve: (value) => {
                    clearTimeout(timer);
                    resolve(value);
                },
                reject: (error) => {
                    clearTimeout(timer);
                    reject(error);
                }
            };
            this.sendMqttMessage(JSON.stringify({
                type: 'mcp',
                payload: { jsonrpc: '2.0', method, id, params }
            }));
        });
    }

    onMcpMessageFromBridge(message) {
        const { method, id, params } = message.payload;
        if (method === 'initialize') {
            this.bridge.sendJson({
                type: 'mcp',
                payload: { jsonrpc: '2.0', id, result: this.mcpCachedInitialize }
            });
        } else if (method === 'tools/list') {
            this.bridge.sendJson({
                type: 'mcp',
                payload: { jsonrpc: '2.0', id, result: { tools: this.mcpCachedTools } }
            });
        } else if (method === 'notifications/initialized') {
            // do nothing
        }
    }
}

class MQTTServer {
    constructor() {
        this.mqttPort = parseInt(process.env.MQTT_PORT) || 1883;
        this.udpPort = parseInt(process.env.UDP_PORT) || this.mqttPort;
        this.publicIp = process.env.PUBLIC_IP || 'mqtt.xiaozhi.me';
        this.connections = new Map(); // connectionId -> MQTTConnection
        this.clientIdMap = new Map(); // clientId -> MQTTConnection
        this.keepAliveTimer = null;
        this.keepAliveCheckInterval = 1000; // 默认每1秒检查一次

        this.headerBuffer = Buffer.alloc(16);
    }

    generateNewConnectionId() {
        // 生成一个32位不重复的整数
        let id;
        do {
            id = Math.floor(Math.random() * 0xFFFFFFFF);
        } while (this.connections.has(id));
        return id;
    }

    start() {
        this.mqttServer = net.createServer((socket) => {
            const connectionId = this.generateNewConnectionId();
            debug(`新客户端连接: ${connectionId}`);
            new MQTTConnection(socket, connectionId, this);
        });

        this.mqttServer.listen(this.mqttPort, () => {
            console.warn(`MQTT 服务器正在监听端口 ${this.mqttPort}`);
        });


        this.udpServer = dgram.createSocket('udp4');
        this.udpServer.on('message', this.onUdpMessage.bind(this));
        this.udpServer.on('error', err => {
            console.error('UDP 错误', err);
            setTimeout(() => { process.exit(1); }, 1000);
        });
        this.udpServer.bind(this.udpPort, () => {
            console.warn(`UDP 服务器正在监听 ${this.publicIp}:${this.udpPort}`);
        });

        // 启动全局心跳检查定时器
        this.setupKeepAliveTimer();
    }

    /**
     * 设置全局心跳检查定时器
     */
    setupKeepAliveTimer() {
        // 清除现有定时器
        this.clearKeepAliveTimer();
        this.lastConnectionCount = 0;
        this.lastActiveConnectionCount = 0;

        // 设置新的定时器
        this.keepAliveTimer = setInterval(() => {
            // 检查所有连接的心跳状态
            for (const connection of this.connections.values()) {
                connection.checkKeepAlive();
            }

            const activeCount = Array.from(this.connections.values()).filter(connection => connection.isAlive()).length;
            if (activeCount !== this.lastActiveConnectionCount || this.connections.size !== this.lastConnectionCount) {
                console.log(`连接数: ${this.connections.size}, 活跃数: ${activeCount}`);
                this.lastActiveConnectionCount = activeCount;
                this.lastConnectionCount = this.connections.size;
            }
        }, this.keepAliveCheckInterval);
    }

    /**
     * 清除心跳检查定时器
     */
    clearKeepAliveTimer() {
        if (this.keepAliveTimer) {
            clearInterval(this.keepAliveTimer);
            this.keepAliveTimer = null;
        }
    }

    addConnection(connection) {
        // 检查是否已存在相同 clientId 的连接
        for (const [key, value] of this.connections.entries()) {
            if (value.clientId === connection.clientId) {
                debug(`${connection.clientId} 已存在连接，关闭旧连接`);
                value.close();
            }
        }
        this.connections.set(connection.connectionId, connection);

        // 添加到索引映射中
        if (connection.clientId) {
            this.clientIdMap.set(connection.clientId, connection);
        }
    }

    removeConnection(connection) {
        debug(`关闭连接: ${connection.connectionId}`);
        if (this.connections.has(connection.connectionId)) {
            this.connections.delete(connection.connectionId);
        }

        if (connection.clientId && this.clientIdMap.has(connection.clientId)) {
            if (this.clientIdMap.get(connection.clientId).connectionId === connection.connectionId) {
                this.clientIdMap.delete(connection.clientId);
            }
        }
    }

    sendUdpMessage(message, remoteAddress) {
        this.udpServer.send(message, remoteAddress.port, remoteAddress.address);
    }

    onUdpMessage(message, rinfo) {
        // message format: [type: 1u, flag: 1u, payloadLength: 2u, cookie: 4u, timestamp: 4u, sequence: 4u, payload: n]
        if (message.length < 16) {
            console.warn('收到不完整的 UDP Header', rinfo);
            return;
        }

        try {
            const type = message.readUInt8(0);
            if (type !== 1) return;

            const payloadLength = message.readUInt16BE(2);
            if (message.length < 16 + payloadLength) return;

            const connectionId = message.readUInt32BE(4);
            const connection = this.connections.get(connectionId);
            if (!connection) return;

            const timestamp = message.readUInt32BE(8);
            const sequence = message.readUInt32BE(12);

            connection.onUdpMessage(rinfo, message, payloadLength, timestamp, sequence);
        } catch (error) {
            console.error('UDP 消息处理错误:', error);
        }
    }

    /**
     * 停止服务器
     */
    async stop() {
        if (this.stopping) {
            return;
        }
        this.stopping = true;
        // 清除心跳检查定时器
        this.clearKeepAliveTimer();

        if (this.connections.size > 0) {
            console.warn(`等待 ${this.connections.size} 个连接关闭`);
            for (const connection of this.connections.values()) {
                connection.close();
            }
            await new Promise(resolve => setTimeout(resolve, 300));
            debug('等待连接关闭完成');
            this.connections.clear();
        }

        if (this.udpServer) {
            this.udpServer.close();
            this.udpServer = null;
            console.warn('UDP 服务器已停止');
        }

        // 关闭MQTT服务器
        if (this.mqttServer) {
            this.mqttServer.close();
            this.mqttServer = null;
            console.warn('MQTT 服务器已停止');
        }

        process.exit(0);
    }

    // 通过clientId查找连接
    getConnectionById(clientId) {
        if (this.clientIdMap.has(clientId)) {
            return this.clientIdMap.get(clientId);
        }
        for (const connection of this.connections.values()) {
            if (connection.clientId && connection.clientId == clientId) {
                console.log('connectionid', connection.connectionId);
                this.clientIdMap.set(connection.clientId, connection);
                return connection;
            }
        }
        return null;
    }
}

// 创建并启动服务器
const server = new MQTTServer();
server.start();
process.on('SIGINT', () => {
    console.warn('收到 SIGINT 信号，开始关闭');
    server.stop();
});

// 添加管理API服务，用于向设备下发指令并获取响应
const express = require('express');
const app = express();
const adminPort = process.env.API_PORT || 8007;

app.use(express.json());

// 计算当天的令牌的辅助函数
function calculateDailyToken() {
    try {
        // 获取当前日期（yyyy-MM-dd格式）
        const now = new Date();
        const year = now.getFullYear();
        const month = String(now.getMonth() + 1).padStart(2, '0');
        const day = String(now.getDate()).padStart(2, '0');
        const currentDate = `${year}-${month}-${day}`;

        // 从环境变量获取签名密钥
        const signatureKey = process.env.MQTT_SIGNATURE_KEY;

        // 计算令牌
        const tokenString = currentDate + signatureKey;
        return crypto.createHash('sha256').update(tokenString).digest('hex');
    } catch (error) {
        console.error('计算令牌失败:', error);
        throw error;
    }
}

// 验证Authorization头的中间件
function authenticateRequest(req, res, next) {
    try {
        // 获取Authorization头
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: '未提供有效的Authorization头' });
        }

        // 提取token
        const token = authHeader.split(' ')[1];

        // 计算预期的token
        const expectedToken = calculateDailyToken();

        // 验证token
        if (token !== expectedToken) {
            return res.status(401).json({ error: '无效的授权令牌' });
        }

        // 验证通过，继续处理请求
        next();
    } catch (error) {
        res.status(401).json({ error: '授权验证失败' });
    }
}

// 设备指令下发API - 支持MCP指令并返回设备响应
app.post('/api/commands/:clientId', authenticateRequest, async (req, res) => {
    try {
        const { clientId } = req.params;
        const command = req.body;
        const targetConnection = server.getConnectionById(clientId);
        if (!targetConnection) {
            return res.status(500).json({ success: false, error: '设备未连接' });
        }

        // 处理MCP类型的命令
        if (command.type === 'mcp' && command.payload) {
            const { method, params } = command.payload;
            try {
                const result = await targetConnection.sendMcpRequest(method, params, 5000);
                res.json({
                    success: true,
                    data: result
                });
            } catch (error) {
                res.status(500).json({
                    success: false,
                    error: error.message
                });
            }
        } else {
            res.status(500).json({ success: false, error: '指令类型无效' });
        }
    } catch (error) {
        console.error('处理指令下发错误:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// 获取指定设备在线状态的API
app.post('/api/devices/status', authenticateRequest, (req, res) => {
    try {
        const { clientIds } = req.body;

        // 验证参数
        if (!clientIds || !Array.isArray(clientIds)) {
            return res.status(400).json({ error: 'clientIds必须是一个数组' });
        }

        // 构建设备状态map
        const deviceStatusMap = {};
        clientIds.forEach(clientId => {
            const connection = server.getConnectionById(clientId);
            deviceStatusMap[clientId] = {
                isAlive: connection ? connection.isAlive() : false,
                exists: !!connection
            };
        });

        res.json(deviceStatusMap);
    } catch (error) {
        console.error('处理设备状态查询错误:', error);
        res.status(500).json({ error: error.message });
    }
});

// 计算并打印当天的临时密钥
function calculateAndPrintDailyToken() {
    try {
        // 调用共享的辅助函数计算令牌
        const dailyToken = calculateDailyToken();

        // 打印令牌信息
        console.log('API今日临时密钥: Authorization: Bearer ' + dailyToken);
        return dailyToken;
    } catch (error) {
        console.error('计算临时密钥失败:', error);
    }
}

// 验证MQTT_SIGNATURE_KEY的密码复杂度
function validateSignatureKeyComplexity() {
    const signatureKey = process.env.MQTT_SIGNATURE_KEY;

    if (!signatureKey) {
        console.error('无法启动管理API服务: 未设置MQTT_SIGNATURE_KEY环境变量');
        return false;
    }

    // 检查长度是否大于等于8位
    if (signatureKey.length < 8) {
        console.error('无法启动管理API服务: MQTT_SIGNATURE_KEY长度必须大于等于8位');
        return false;
    }

    // 检查是否包含大写字母
    if (!/[A-Z]/.test(signatureKey)) {
        console.error('无法启动管理API服务: MQTT_SIGNATURE_KEY必须包含至少一个大写字母');
        return false;
    }

    // 检查是否包含小写字母
    if (!/[a-z]/.test(signatureKey)) {
        console.error('无法启动管理API服务: MQTT_SIGNATURE_KEY必须包含至少一个小写字母');
        return false;
    }

    // 检查是否包含不允许的字符串
    const forbiddenStrings = ['test', '1234', 'admin', 'password', 'qwerty', 'xiaozhi'];
    for (const forbidden of forbiddenStrings) {
        if (signatureKey.toLowerCase().includes(forbidden)) {
            console.error(`无法启动管理API服务: MQTT_SIGNATURE_KEY不能包含'${forbidden}'弱密码，请更换后重启本服务`);
            return false;
        }
    }

    return true;
}

// 启动管理API服务
if (validateSignatureKeyComplexity()) {
    app.listen(adminPort, () => {
        console.log(`管理API服务启动在端口 ${adminPort}`);
        // 计算并打印当天的临时密钥
        calculateAndPrintDailyToken();
    });
}
