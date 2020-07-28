package com.airbus_cyber_security.graylog.events.processor.aggregation;

import com.google.common.collect.Lists;
import com.google.inject.assistedinject.Assisted;
import org.graylog.events.event.Event;
import org.graylog.events.event.EventFactory;
import org.graylog.events.event.EventOriginContext;
import org.graylog.events.event.EventWithContext;
import org.graylog.events.processor.*;
import org.graylog.events.search.MoreSearch;
import org.graylog2.indexer.messages.Messages;
import org.graylog2.indexer.results.ResultMessage;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.indexer.searches.timeranges.TimeRange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.function.Consumer;

public class AggregationCountProcessor implements EventProcessor {
    public interface Factory extends EventProcessor.Factory<AggregationCountProcessor> {
        @Override
        AggregationCountProcessor create(EventDefinition eventDefinition);
    }

    private static final Logger LOG = LoggerFactory.getLogger(AggregationCountProcessor.class);

    private final EventDefinition eventDefinition;
    private final AggregationCountProcessorConfig configuration;
    private final EventProcessorDependencyCheck dependencyCheck;
    private final DBEventProcessorStateService stateService;
    private final Messages messages;
    private final AggregationCount aggregationCount;

    @Inject
    public AggregationCountProcessor(@Assisted EventDefinition eventDefinition, EventProcessorDependencyCheck dependencyCheck,
                                     DBEventProcessorStateService stateService, MoreSearch moreSearch, Messages messages) {
        this.eventDefinition = eventDefinition;
        this.configuration = (AggregationCountProcessorConfig) eventDefinition.config();
        this.dependencyCheck = dependencyCheck;
        this.stateService = stateService;
        this.messages = messages;
        this.aggregationCount = new AggregationCount(moreSearch, this.configuration);
    }

    @Override
    public void createEvents(EventFactory eventFactory, EventProcessorParameters eventProcessorParameters, EventConsumer<List<EventWithContext>> eventConsumer) throws EventProcessorException {
        final AggregationCountProcessorParameters parameters = (AggregationCountProcessorParameters) eventProcessorParameters;

        TimeRange timerange = parameters.timerange();
        // TODO: We have to take the Elasticsearch index.refresh_interval into account here!
        if (!this.dependencyCheck.hasMessagesIndexedUpTo(timerange.getTo())) {
            final String msg = String.format(Locale.ROOT, "Couldn't run aggregation count <%s/%s> for timerange <%s to %s> because required messages haven't been indexed, yet.",
                    eventDefinition.title(), eventDefinition.id(), timerange.getFrom(), timerange.getTo());
            throw new EventProcessorPreconditionException(msg, eventDefinition);
        }

        AggregationCountCheckResult aggregationCountCheckResult = this.aggregationCount.runCheck(timerange);

        List<EventWithContext> listEvents = new ArrayList<>();
        for (MessageSummary messageSummary: aggregationCountCheckResult.getMessageSummaries()) {
            Event event = eventFactory.createEvent(eventDefinition, timerange.getFrom(), aggregationCountCheckResult.getResultDescription());
            event.setOriginContext(EventOriginContext.elasticsearchMessage(messageSummary.getIndex(), messageSummary.getId()));
            EventWithContext eventWithContext = EventWithContext.create(event, messageSummary.getRawMessage());
            LOG.debug("Created event: [id: " + event.getId() + "], [message: " + event.getMessage() + "].");
            listEvents.add(eventWithContext);
        }
        eventConsumer.accept(listEvents);

        // Update the state for this processor! This state will be used for dependency checks between event processors.
        stateService.setState(eventDefinition.id(), timerange.getFrom(), timerange.getTo());
    }

    @Override
    public void sourceMessagesForEvent(Event event, Consumer<List<MessageSummary>> messageConsumer, long limit) throws EventProcessorException {
        if (limit <= 0) {
            return;
        }
        final EventOriginContext.ESEventOriginContext esContext =
                EventOriginContext.parseESContext(event.getOriginContext()).orElseThrow(
                        () -> new EventProcessorException("Failed to parse origin context", false, eventDefinition));
        try {
            final ResultMessage message;
            message = messages.get(esContext.messageId(), esContext.indexName());
            messageConsumer.accept(Lists.newArrayList(new MessageSummary(message.getIndex(), message.getMessage())));
        } catch (IOException e) {
            throw new EventProcessorException("Failed to query origin context message", false, eventDefinition, e);
        }
    }

}
