<?php

namespace Laravel\Octane\Swoole\Handlers;

use Laravel\Octane\Swoole\WorkerState;
use Swoole\WebSocket\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Timer;

class OnWebSocketHandshake
{
    public function __construct(protected Server $server,
                                protected array $serverState,
                                protected WorkerState $workerState)
    {
    }

    /**
     * Handle the "handshake" Swoole event.
     *
     * @param Request $request
     * @param Response $response
     * @return bool
     */
    public function __invoke(Request $request, Response $response): bool
    {
        $secWebSocketKey = $request->header['sec-websocket-key'];
        $patten = '#^[+/0-9A-Za-z]{21}[AQgw]==$#';

        if (0 === preg_match($patten, $secWebSocketKey) || 16 !== strlen(base64_decode($secWebSocketKey))) {
            $response->end();
            return false;
        }

        echo "received key: " . $request->header['sec-websocket-key'] . PHP_EOL;

        $key = base64_encode(sha1($request->header['sec-websocket-key'] . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11', true));

        $headers = [
            'Upgrade' => 'websocket',
            'Connection' => 'Upgrade',
            'Sec-WebSocket-Accept' => $key,
            'Sec-WebSocket-Version' => '13',
        ];

        // WebSocket connection to 'ws://127.0.0.1:9502/'
        // failed: Error during WebSocket handshake:
        // Response must not include 'Sec-WebSocket-Protocol' header if not present in request: websocket
        if (isset($request->header['sec-websocket-protocol'])) {
            $headers['Sec-WebSocket-Protocol'] = $request->header['sec-websocket-protocol'];
        }

        foreach ($headers as $key => $val) {
            $response->header($key, $val);
        }

        $response->status(101);
        $response->end();
        echo "handshake complete" . PHP_EOL;

        $this->server->defer(function () use ($request) {
            echo "connection open: {$request->fd}\n";

            $this->server->tick(1000, function($id) use($request) {
                if ($this->server->exist($request->fd)) {
                    echo "pushing tick to: {$request->fd}\n";
                    $this->server->push($request->fd, json_encode(["tick", time()]));
                } else {
                    $this->server->clearTimer($id);
                }
            });
        });

        return true;
    }
}
