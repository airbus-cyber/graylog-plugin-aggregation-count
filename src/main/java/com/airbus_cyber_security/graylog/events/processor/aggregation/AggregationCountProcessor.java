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

package com.airbus_cyber_security.graylog.events.processor.aggregation;

import com.airbus_cyber_security.graylog.events.processor.aggregation.checks.AggregationCount;
import com.airbus_cyber_security.graylog.events.processor.aggregation.checks.AggregationField;
import com.airbus_cyber_security.graylog.events.processor.aggregation.checks.Result;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.common.primitives.Ints;
import com.google.inject.assistedinject.Assisted;
import org.graylog.events.event.Event;
import org.graylog.events.event.EventFactory;
import org.graylog.events.event.EventOriginContext;
import org.graylog.events.event.EventWithContext;
import org.graylog.events.processor.*;
import org.graylog.events.search.MoreSearch;
import org.graylog.plugins.views.search.Parameter;
import org.graylog2.indexer.messages.Messages;
import org.graylog2.indexer.results.ResultMessage;
import org.graylog2.indexer.results.TermsResult;
import org.graylog2.indexer.searches.Sorting;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.indexer.searches.timeranges.AbsoluteRange;
import org.graylog2.plugin.indexer.searches.timeranges.TimeRange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

public class AggregationCountProcessor implements EventProcessor {
    public interface Factory extends EventProcessor.Factory<AggregationCountProcessor> {
        @Override
        AggregationCountProcessor create(EventDefinition eventDefinition);
    }

    private static final Logger LOG = LoggerFactory.getLogger(AggregationCountProcessor.class);

    private final EventDefinition eventDefinition;
    private final EventProcessorDependencyCheck dependencyCheck;
    private final DBEventProcessorStateService stateService;
    private final Messages messages;
    private final AggregationCount aggregationCount;
    private final AggregationCountProcessorConfig configuration;
    private final MoreSearch moreSearch;

    @Inject
    public AggregationCountProcessor(@Assisted EventDefinition eventDefinition, EventProcessorDependencyCheck dependencyCheck,
                                     DBEventProcessorStateService stateService, MoreSearch moreSearch, Messages messages) {
        this.eventDefinition = eventDefinition;
        this.dependencyCheck = dependencyCheck;
        this.stateService = stateService;
        this.messages = messages;
        this.configuration = (AggregationCountProcessorConfig) eventDefinition.config();
        this.aggregationCount = new AggregationCount(moreSearch, configuration);
        this.moreSearch = moreSearch;
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

        Result aggregationCountCheckResult = this.aggregationCount.runCheck(timerange);
        Event event = eventFactory.createEvent(eventDefinition, timerange.getFrom(), aggregationCountCheckResult.getResultDescription());
        event.addSourceStream(configuration.stream());

        event.setTimerangeStart(timerange.getFrom());
        event.setTimerangeEnd(timerange.getTo());

        if(aggregationCountCheckResult.getMessageSummaries() != null && !aggregationCountCheckResult.getMessageSummaries().isEmpty()) {
            MessageSummary msgSummary = aggregationCountCheckResult.getMessageSummaries().get(0);
            event.setOriginContext(EventOriginContext.elasticsearchMessage(msgSummary.getIndex(), msgSummary.getId()));
            LOG.debug("Created event: [id: " + event.getId() + "], [message: " + event.getMessage() + "].");

            final ImmutableList.Builder<EventWithContext> listEvents = ImmutableList.builder();
            // TODO: Choose a better message for the context
            EventWithContext eventWithContext = EventWithContext.create(event, msgSummary.getRawMessage());
            listEvents.add(eventWithContext);

            eventConsumer.accept(listEvents.build());
        }
        // Update the state for this processor! This state will be used for dependency checks between event processors.
        stateService.setState(eventDefinition.id(), timerange.getFrom(), timerange.getTo());
    }

    @Override
    public void sourceMessagesForEvent(Event event, Consumer<List<MessageSummary>> messageConsumer, long limit) throws EventProcessorException {
        if (limit <= 0) {
            return;
        }

        final TimeRange timeRange = AbsoluteRange.create(event.getTimerangeStart(), event.getTimerangeEnd());
        boolean hasFields = !(configuration.groupingFields().isEmpty() && configuration.distinctionFields().isEmpty());
        if (hasFields) {
            AggregationField aggregationField = new AggregationField(configuration, moreSearch, (int) limit, null);

            final String filter = "streams:" + this.configuration.stream();
            String firstField = aggregationField.getFields().iterator().next();
            List<String> nextFields = new ArrayList<>(aggregationField.getFields());
            nextFields.remove(0);

            /* Get the matched term */
            TermsResult result = this.moreSearch.terms(firstField, nextFields, (int) limit, this.configuration.searchQuery(), filter, timeRange, Sorting.Direction.DESC);
            Map<String, List<String>> matchedTerms = new HashMap<>();
            long  ruleCount = aggregationField.getMatchedTerm(matchedTerms, result);

            /* Get the list of summary messages */
            List<MessageSummary> summaries = Lists.newArrayListWithCapacity((int) limit);
            aggregationField.getListMessageSummary(summaries, matchedTerms, firstField, nextFields, timeRange, filter);

            messageConsumer.accept(summaries);
        } else {
            final AtomicLong msgCount = new AtomicLong(0L);
            final MoreSearch.ScrollCallback callback = (messages, continueScrolling) -> {

                final List<MessageSummary> summaries = Lists.newArrayList();
                for (final ResultMessage resultMessage : messages) {
                    if (msgCount.incrementAndGet() > limit) {
                        continueScrolling.set(false);
                        break;
                    }
                    final Message msg = resultMessage.getMessage();
                    summaries.add(new MessageSummary(resultMessage.getIndex(), msg));
                }
                messageConsumer.accept(summaries);
            };
            Set<String> streams = new HashSet<>();
            streams.add(configuration.stream());
            Set<Parameter> parameters = new HashSet<>();
            moreSearch.scrollQuery(configuration.searchQuery(), streams, parameters, timeRange, Math.min(500, Ints.saturatedCast(limit)), callback);
        }
    }

}
