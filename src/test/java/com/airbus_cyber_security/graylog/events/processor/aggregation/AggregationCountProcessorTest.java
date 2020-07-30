package com.airbus_cyber_security.graylog.events.processor.aggregation;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.graylog.events.event.*;
import org.graylog.events.notifications.EventNotificationSettings;
import org.graylog.events.processor.*;
import org.graylog.events.search.MoreSearch;
import org.graylog2.indexer.messages.Messages;
import org.graylog2.indexer.results.CountResult;
import org.graylog2.plugin.Tools;
import org.graylog2.plugin.indexer.searches.timeranges.AbsoluteRange;
import org.graylog2.plugin.indexer.searches.timeranges.TimeRange;
import org.graylog2.plugin.streams.Stream;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import java.util.HashSet;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

public class AggregationCountProcessorTest {

    @Rule
    public final MockitoRule mockitoRule = MockitoJUnit.rule();

    @Mock
    private EventFactory eventFactory;
    @Mock
    private DBEventProcessorStateService stateService;
    @Mock
    private EventProcessorDependencyCheck dependencyCheck;
    @Mock
    private MoreSearch moreSearch;
    @Mock
    private Messages messages;

    private AggregationCountProcessor subject;

    @Before
    public void setUp() {
        AggregationCountProcessorConfig configuration = AggregationCountProcessorConfig.builder()
                .stream("main stream")
                .thresholdType(AggregationCount.ThresholdType.MORE.getDescription())
                .threshold(100)
                .searchWithinMs(2 * 1000)
                .executeEveryMs(2 * 60 * 1000)
                .messageBacklog(1)
                .groupingFields(new HashSet<>())
                .distinctionFields(new HashSet<>())
                .comment("test comment")
                .searchQuery("*")
                .repeatNotifications(false)
                .build();
        EventDefinition eventDefinition = EventDefinitionDto.builder()
                .id("dto-id")
                .title("Test Correlation")
                .description("A test correlation event processors")
                .config(configuration)
                .alert(false)
                .keySpec(ImmutableList.of())
                .notificationSettings(EventNotificationSettings.withGracePeriod(60000))
                .priority(1)
                .build();

        this.subject = new AggregationCountProcessor(eventDefinition, this.dependencyCheck,
                stateService, moreSearch, messages);

    }

    @Test
    public void createEventsShouldThrowWhenMessagesAreNotYetIndexed() {
        DateTime now = DateTime.now(DateTimeZone.UTC);
        AbsoluteRange timeRange = AbsoluteRange.create(now.minusHours(1), now.plusHours(1));
        AggregationCountProcessorParameters parameters = AggregationCountProcessorParameters.builder()
                .timerange(timeRange)
                .build();

        assertThatThrownBy(() -> this.subject.createEvents(eventFactory, parameters, (events) -> {}))
                .hasMessageContaining("Test Correlation")
                .hasMessageContaining("dto-id")
                .hasMessageContaining(timeRange.from().toString())
                .hasMessageContaining(timeRange.to().toString())
                .isInstanceOf(EventProcessorPreconditionException.class);
    }

    @Test
    public void createEventsShouldNotFailWhenThereAreNoMessages() throws EventProcessorException {
        DateTime now = DateTime.now(DateTimeZone.UTC);
        AbsoluteRange timeRange = AbsoluteRange.create(now.minusHours(1), now.plusHours(1));
        AggregationCountProcessorParameters parameters = AggregationCountProcessorParameters.builder()
                .timerange(timeRange)
                .build();

        when(this.dependencyCheck.hasMessagesIndexedUpTo(any(DateTime.class))).thenReturn(true);
        EventConsumer<List<EventWithContext>> eventConsumer = Mockito.mock(EventConsumer.class);
        when(this.moreSearch.count(anyString(), any(TimeRange.class), anyString())).thenReturn(CountResult.create(0, 0));
        EventDto eventDto = EventDto.builder()
                .alert(true)
                .eventDefinitionId("EventDefinitionTestId")
                .eventDefinitionType("notification-test-v1")
                .eventTimestamp(Tools.nowUTC())
                .processingTimestamp(Tools.nowUTC())
                .id("NotificationTestId")
                .streams(ImmutableSet.of(Stream.DEFAULT_EVENTS_STREAM_ID))
                .message("Notification test message triggered from user <user>")
                .source(Stream.DEFAULT_STREAM_ID)
                .keyTuple(ImmutableList.of("testkey"))
                .key("testkey")
                .originContext(EventOriginContext.elasticsearchMessage("testIndex_42", "b5e53442-12bb-4374-90ed-0deadbeefbaz"))
                .priority(2)
                .fields(ImmutableMap.of("field1", "value1", "field2", "value2"))
                .build();
        Event event = Event.fromDto(eventDto);
        when(this.eventFactory.createEvent(any(EventDefinition.class), any(DateTime.class), anyString())).thenReturn(event);
        this.subject.createEvents(this.eventFactory, parameters, eventConsumer);
    }
}
