/*
 * graylog-plugin-aggregation-count Source Code
 * Copyright (C) 2018-2020 - Airbus CyberSecurity (SAS) - All rights reserved
 *
 * This file is part of the graylog-plugin-aggregation-count GPL Source Code.
 *
 * graylog-plugin-aggregation-count Source Code is free software:
 * you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * This code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this code.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.airbus_cyber_security.graylog.events;

import java.util.Collections;
import java.util.Set;

import com.airbus_cyber_security.graylog.events.processor.aggregation.AggregationCountProcessor;
import com.airbus_cyber_security.graylog.events.processor.aggregation.AggregationCountProcessorParameters;
import com.airbus_cyber_security.graylog.events.processor.aggregation.AggregationCountProcessorConfig;
import com.airbus_cyber_security.graylog.events.contentpack.entities.AggregationCountProcessorConfigEntity;
import org.graylog2.plugin.PluginConfigBean;
import org.graylog2.plugin.PluginModule;

public class AggregationCountModule extends PluginModule {
    /**
     * Returns all configuration beans required by this plugin.
     *
     * Implementing this method is optional. The default method returns an empty {@link Set}.
     */
    @Override
    public Set<? extends PluginConfigBean> getConfigBeans() {
        return Collections.emptySet();
    }

    @Override
    protected void configure() {
        registerJacksonSubtype(AggregationCountProcessorConfigEntity.class,
                AggregationCountProcessorConfigEntity.TYPE_NAME);

        addEventProcessor(AggregationCountProcessorConfig.TYPE_NAME,
                AggregationCountProcessor.class,
                AggregationCountProcessor.Factory.class,
                AggregationCountProcessorConfig.class,
                AggregationCountProcessorParameters.class);
    }
}
