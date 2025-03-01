<?php

namespace Laravel\Octane\Listeners;

class GiveNewApplicationInstanceToViewFactory
{
    /**
     * Handle the event.
     *
     * @param  mixed  $event
     * @return void
     */
    public function handle($event): void
    {
        with($event->sandbox->make('view'), function ($view) use ($event) {
            $view->setContainer($event->sandbox);

            $view->share('app', $event->sandbox);
        });
    }
}
