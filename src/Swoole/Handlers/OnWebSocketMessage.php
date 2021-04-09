<?php

namespace Laravel\Octane\Swoole\Handlers;

use Laravel\Octane\Swoole\WorkerState;
use Swoole\WebSocket\Server;
use Swoole\WebSocket\Frame;

class OnWebSocketMessage
{
    public function __construct(protected array $serverState,
                                protected WorkerState $workerState)
    {
    }

    /**
     * Handle the "message" Swoole event.
     *
     * @param \Swoole\WebSocket\Server $server
     * @param Frame $frame
     * @return void
     */
    public function __invoke(Server $server, Frame $frame)
    {
        echo "received message: {$frame->data}\n";
        $server->push($frame->fd, json_encode(["message", time()]));
    }
}
