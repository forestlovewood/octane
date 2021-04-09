<?php

namespace Laravel\Octane\Swoole\Handlers;

use Laravel\Octane\Swoole\WorkerState;
use Swoole\WebSocket\Server;

class OnWebSocketClose
{
    public function __construct(protected array $serverState,
                                protected WorkerState $workerState)
    {
    }

    /**
     * Handle the "close" Swoole event.
     *
     * @param Server $server
     * @param int $fd
     * @return void
     */
    public function __invoke(Server $server, int $fd)
    {
        echo "connection close: {$fd}\n";
    }
}
