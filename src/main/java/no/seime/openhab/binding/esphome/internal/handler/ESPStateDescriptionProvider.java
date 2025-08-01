/*
 * Copyright (c) 2010-2025 Contributors to the openHAB project
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

import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.openhab.core.thing.Channel;
import org.openhab.core.thing.ChannelUID;
import org.openhab.core.thing.ThingUID;
import org.openhab.core.thing.type.DynamicCommandDescriptionProvider;
import org.openhab.core.thing.type.DynamicStateDescriptionProvider;
import org.openhab.core.types.CommandDescription;
import org.openhab.core.types.StateDescription;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provides state and command descriptions for individual channels.
 *
 * @author Cody Cutrer- Initial contribution
 */
@Component(service = { DynamicStateDescriptionProvider.class, DynamicCommandDescriptionProvider.class,
        ESPStateDescriptionProvider.class })
@NonNullByDefault
public class ESPStateDescriptionProvider implements DynamicStateDescriptionProvider, DynamicCommandDescriptionProvider {

    private final Map<ChannelUID, StateDescription> stateDescriptions = new ConcurrentHashMap<>();
    private final Map<ChannelUID, CommandDescription> commandDescriptions = new ConcurrentHashMap<>();
    private final Logger logger = LoggerFactory.getLogger(ESPStateDescriptionProvider.class);

    @Activate
    public ESPStateDescriptionProvider() {
    }

    /**
     * Set a state description for a channel. This description will be used when preparing the channel state by
     * the framework for presentation. A previous description, if existed, will be replaced.
     *
     * @param channelUID channel UID
     * @param description state description for the channel
     */
    public void setDescription(ChannelUID channelUID, StateDescription description) {
        stateDescriptions.put(channelUID, description);
    }

    /**
     * Set a command description for a channel.
     * A previous description, if existed, will be replaced.
     *
     * @param channelUID channel UID
     * @param description command description for the channel
     */
    public void setDescription(ChannelUID channelUID, CommandDescription description) {
        commandDescriptions.put(channelUID, description);
    }

    public void removeDescriptionsForThing(ThingUID thingUID) {
        stateDescriptions.keySet().removeIf(channelUID -> channelUID.getThingUID().equals(thingUID));
        commandDescriptions.keySet().removeIf(channelUID -> channelUID.getThingUID().equals(thingUID));
    }

    @Override
    public @Nullable StateDescription getStateDescription(Channel channel,
            @Nullable StateDescription originalStateDescription, @Nullable Locale locale) {
        return stateDescriptions.get(channel.getUID());
    }

    @Override
    public @Nullable CommandDescription getCommandDescription(Channel channel,
            @Nullable CommandDescription originalCommandDescription, @Nullable Locale locale) {
        return commandDescriptions.get(channel.getUID());
    }
}
