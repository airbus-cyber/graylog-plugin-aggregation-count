package com.airbus_cyber_security.graylog;

import java.util.Collections;
import java.util.Set;

import com.airbus_cyber_security.graylog.config.AggregationCountProcessorConfig;
import org.graylog.events.processor.EventProcessorEngine;
import org.graylog.events.processor.EventProcessorExecutionMetrics;
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
        bind(EventProcessorEngine.class).asEagerSingleton();
        bind(EventProcessorExecutionMetrics.class).asEagerSingleton();
        addEventProcessor(AggregationCountProcessorConfig.TYPE_NAME,
                AggregationCountProcessor.class,
                AggregationCountProcessor.Factory.class,
                AggregationCountProcessorConfig.class,
                AggregationCountProcessorParameters.class);
    }
}
