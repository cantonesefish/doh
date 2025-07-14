// SPDX-License-Identifier: 0BSD

const doh = 'https://security.cloudflare-dns.com/dns-query ';
const dohjson = 'https://security.cloudflare-dns.com/dns-query ';
const contype = 'application/dns-message';
const jstontype = 'application/dns-json';
const path = ''; // 路径白名单（默认允许所有）

const r404 = new Response(null, { status: 404 });

export default {
    async fetch(request) {
        return handleRequest(request);
    }
};

async function handleRequest(request) {
    const { method, headers, url } = request;
    const clientIP = headers.get('CF-Connecting-IP'); // 获取客户端IP [[5]]
    const ecs = getECS(clientIP); // 生成子网信息
    
    const parsedUrl = new URL(url);
    const { searchParams, pathname } = parsedUrl;

    // 路径检查
    if (!pathname.startsWith(path)) return r404;

    // 处理JSON格式请求（添加edns_client_subnet参数）
    if (method === 'GET' && headers.get('Accept') === jstontype) {
        const params = new URLSearchParams(parsedUrl.search);
        if (ecs) params.set('edns_client_subnet', ecs); // 添加ECS参数 [[5]]
        return fetch(`${dohjson}?${params.toString()}`, {
            headers: { 'Accept': jstontype }
        });
    }

    // 处理Base64编码的GET请求（修改DNS消息）
    if (method === 'GET' && searchParams.has('dns')) {
        let dnsQuery = searchParams.get('dns');
        
        try {
            // Base64URL解码 [[7]]
            const padding = '='.repeat((4 - (dnsQuery.length % 4)) % 4);
            const raw = atob(dnsQuery.replace(/-/g, '+').replace(/_/g, '/') + padding);
            const dnsMessage = new Uint8Array([...raw].map(c => c.charCodeAt(0)));

            // 修改DNS消息（添加EDNS OPT记录和ECS选项）
            // 注意：此处为简化示例，实际需实现DNS协议解析（参考RFC1035）
            const modifiedMessage = addECSOption(dnsMessage, ecs);

            // Base64URL重新编码
            const modifiedQuery = btoa(String.fromCharCode(...modifiedMessage))
                .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

            return fetch(`${doh}?dns=${modifiedQuery}`, {
                headers: { 'Accept': contype }
            });
        } catch (e) {
            return new Response('DNS message modification failed', { status: 400 });
        }
    }

    // 暂不支持POST请求（处理复杂且需流式解析）
    if (method === 'POST' && headers.get('content-type') === contype) {
        return new Response('ECS not supported for POST requests', { status: 400 });
    }

    return r404;
}

// 生成ECS子网信息 [[5]]
function getECS(ip) {
    if (!ip) return '';
    if (ip.includes('.')) {
        // IPv4 (/24子网)
        const parts = ip.split('.');
        return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
    } else if (ip.includes(':')) {
        // IPv6 (/64子网)
        const parts = ip.split(':');
        return `${parts.slice(0, 2).join(':')}::/64`;
    }
    return '';
}

// 模拟DNS消息修改（实际需完整DNS协议解析）
function addECSOption(message, ecs) {
    // 实际实现需解析DNS消息结构并添加EDNS OPT记录
    // 此处仅为占位符（完整实现需参考dns-message或doh-encoder库）
    console.warn('DNS message modification requires full protocol parsing');
    return message; // 返回未修改的原始消息
}
