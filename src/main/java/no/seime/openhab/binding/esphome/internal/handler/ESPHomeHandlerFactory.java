/**
 * Copyright (c) 2023 Contributors to the Seime Openhab Addons project
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 */
package no.seime.openhab.binding.esphome.internal.handler;

import java.io.IOException;
import java.util.Set;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.atomic.AtomicLong;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.openhab.core.items.ItemRegistry;
import org.openhab.core.thing.Thing;
import org.openhab.core.thing.ThingRegistry;
import org.openhab.core.thing.ThingTypeUID;
import org.openhab.core.thing.binding.BaseThingHandlerFactory;
import org.openhab.core.thing.binding.ThingHandler;
import org.openhab.core.thing.binding.ThingHandlerFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import no.seime.openhab.binding.esphome.internal.BindingConstants;
import no.seime.openhab.binding.esphome.internal.comm.ConnectionSelector;
import no.seime.openhab.binding.esphome.internal.message.statesubscription.ESPHomeEventSubscriber;

/**
 * The {@link ESPHomeHandlerFactory} is responsible for creating things and thing
 * handlers.
 *
 * @author Arne Seime - Initial contribution
 */
@NonNullByDefault
@Component(configurationPid = "binding.esphome", service = ThingHandlerFactory.class)
public class ESPHomeHandlerFactory extends BaseThingHandlerFactory {

    private final Logger logger = LoggerFactory.getLogger(ESPHomeHandlerFactory.class);

    private static final Set<ThingTypeUID> SUPPORTED_THING_TYPES_UIDS = Set.of(BindingConstants.THING_TYPE_DEVICE);

    private final AtomicLong threadCounter = new AtomicLong(0);

    @Override
    public boolean supportsThingType(ThingTypeUID thingTypeUID) {
        return SUPPORTED_THING_TYPES_UIDS.contains(thingTypeUID);
    }

    private final ConnectionSelector connectionSelector;

    private final ESPChannelTypeProvider dynamicChannelTypeProvider;
    private final ESPHomeEventSubscriber eventSubscriber;

    private ScheduledExecutorService scheduler;

    @Activate
    public ESPHomeHandlerFactory(@Reference ESPChannelTypeProvider dynamicChannelTypeProvider,
            @Reference ESPHomeEventSubscriber eventSubscriber, @Reference ItemRegistry itemRegistry,
            @Reference ThingRegistry thingRegistry) throws IOException {
        scheduler = new MonitoredScheduledThreadPoolExecutor(2, r -> {
            long currentCount = threadCounter.incrementAndGet();
            logger.debug("Creating new worker thread {} for scheduler", currentCount);
            Thread t = new Thread(r);
            t.setDaemon(true);
            t.setName("ESPHome scheduler worker thread " + currentCount);
            return t;
        });

        this.dynamicChannelTypeProvider = dynamicChannelTypeProvider;

        this.eventSubscriber = eventSubscriber;
        eventSubscriber.setItemRegistry(itemRegistry);
        eventSubscriber.setThingRegistry(thingRegistry);

        connectionSelector = new ConnectionSelector();
    }

    @Override
    protected @Nullable ThingHandler createHandler(Thing thing) {
        ThingTypeUID thingTypeUID = thing.getThingTypeUID();

        if (BindingConstants.THING_TYPE_DEVICE.equals(thingTypeUID)) {
            return new ESPHomeHandler(thing, connectionSelector, dynamicChannelTypeProvider, eventSubscriber,
                    scheduler);
        }

        return null;
    }

    @Override
    protected void activate(ComponentContext componentContext) {
        super.activate(componentContext);
        connectionSelector.start();
    }

    @Override
    protected void deactivate(ComponentContext componentContext) {
        scheduler.shutdown();
        try {
            scheduler.awaitTermination(10, java.util.concurrent.TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            logger.warn("Scheduler did not terminate in time. This may indicate ESPs with hanging connections");
        }
        connectionSelector.stop();

        super.deactivate(componentContext);
    }
}
