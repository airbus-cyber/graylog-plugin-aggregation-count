package com.airbus_cyber_security.graylog.events.processor.aggregation;

import com.airbus_cyber_security.graylog.events.contentpack.entities.AggregationCountProcessorConfigEntity;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.google.auto.value.AutoValue;
import com.google.common.graph.MutableGraph;
import org.graylog.events.contentpack.entities.EventProcessorConfigEntity;
import org.graylog.events.processor.EventDefinition;
import org.graylog.events.processor.EventProcessorConfig;
import org.graylog.events.processor.EventProcessorExecutionJob;
import org.graylog.events.processor.EventProcessorSchedulerConfig;
import org.graylog.scheduler.clock.JobSchedulerClock;
import org.graylog.scheduler.schedule.IntervalJobSchedule;
import org.graylog2.contentpacks.EntityDescriptorIds;
import org.graylog2.contentpacks.model.ModelId;
import org.graylog2.contentpacks.model.ModelTypes;
import org.graylog2.contentpacks.model.entities.EntityDescriptor;
import org.graylog2.contentpacks.model.entities.references.ValueReference;
import org.graylog2.plugin.indexer.searches.timeranges.AbsoluteRange;
import org.graylog2.plugin.rest.ValidationResult;
import org.graylog2.shared.security.RestPermissions;
import org.joda.time.DateTime;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;

@AutoValue
@JsonTypeName(AggregationCountProcessorConfig.TYPE_NAME)
@JsonDeserialize(builder = AggregationCountProcessorConfig.Builder.class)
public abstract class AggregationCountProcessorConfig implements EventProcessorConfig {

    public static final String TYPE_NAME = "aggregation-count";

    private static final String FIELD_STREAM = "stream";
    private static final String FIELD_THRESHOLD_TYPE = "threshold_type";
    private static final String FIELD_THRESHOLD = "threshold";
    private static final String FIELD_GRACE_PERIOD = "grace_period";
    private static final String FIELD_MESSAGE_BACKLOG = "message_backlog";
    private static final String FIELD_GROUPING_FIELDS = "grouping_fields";
    private static final String FIELD_DISTINCTION_FIELDS = "distinction_fields";
    private static final String FIELD_COMMENT = "comment";
    private static final String FIELD_SEARCH_QUERY = "search_query";
    private static final String FIELD_REPEAT_NOTIFICATIONS = "repeat_notifications";
    private static final String FIELD_SEARCH_WITHIN_MS = "search_within_ms";

    @JsonProperty(FIELD_STREAM)
    public abstract String stream();

    @JsonProperty(FIELD_THRESHOLD_TYPE)
    public abstract String thresholdType();

    @JsonProperty(FIELD_THRESHOLD)
    public abstract int threshold();

    @JsonProperty(FIELD_GRACE_PERIOD)
    public abstract int gracePeriod();

    @JsonProperty(FIELD_MESSAGE_BACKLOG)
    public abstract int messageBacklog();

    @JsonProperty(FIELD_GROUPING_FIELDS)
    public abstract Set<String> groupingFields();

    @JsonProperty(FIELD_DISTINCTION_FIELDS)
    public abstract Set<String> distinctionFields();

    @JsonProperty(FIELD_COMMENT)
    public abstract String comment();

    @JsonProperty(FIELD_SEARCH_QUERY)
    public abstract String searchQuery();

    @JsonProperty(FIELD_REPEAT_NOTIFICATIONS)
    public abstract boolean repeatNotifications();

    @JsonProperty(FIELD_SEARCH_WITHIN_MS)
    public abstract long searchWithinMs();

    @Override
    public Set<String> requiredPermissions() {
        return Collections.singleton(RestPermissions.STREAMS_READ);
    }

    public static Builder builder() {
        return Builder.create();
    }

    public abstract Builder toBuilder();

    @Override
    public Optional<EventProcessorSchedulerConfig> toJobSchedulerConfig(EventDefinition eventDefinition, JobSchedulerClock clock) {

        long executeEveryMs = gracePeriod()*60*1000;

        final DateTime now = clock.nowUTC();

        // We need an initial timerange for the first execution of the event processor
        final AbsoluteRange timerange = AbsoluteRange.create(now.minus(searchWithinMs()), now);

        final EventProcessorExecutionJob.Config jobDefinitionConfig = EventProcessorExecutionJob.Config.builder()
                .eventDefinitionId(eventDefinition.id())
                .processingWindowSize(searchWithinMs())
                .processingHopSize(executeEveryMs)
                .parameters(AggregationCountProcessorParameters.builder()
                        .timerange(timerange)
                        .build())
                .build();
        final IntervalJobSchedule schedule = IntervalJobSchedule.builder()
                .interval(executeEveryMs)
                .unit(TimeUnit.MILLISECONDS)
                .build();

        return Optional.of(EventProcessorSchedulerConfig.create(jobDefinitionConfig, schedule));
    }

    @AutoValue.Builder
    public static abstract class Builder implements EventProcessorConfig.Builder<Builder> {
        @JsonCreator
        public static Builder create() {
            return new AutoValue_AggregationCountProcessorConfig.Builder()
                    .type(TYPE_NAME);
        }

        @JsonProperty(FIELD_STREAM)
        public abstract Builder stream(String stream);

        @JsonProperty(FIELD_THRESHOLD_TYPE)
        public abstract Builder thresholdType(String thresholdType);

        @JsonProperty(FIELD_THRESHOLD)
        public abstract Builder threshold(int threshold);

        @JsonProperty(FIELD_GRACE_PERIOD)
        public abstract Builder gracePeriod(int gracePeriod);

        @JsonProperty(FIELD_MESSAGE_BACKLOG)
        public abstract Builder messageBacklog(int messageBacklog);

        @JsonProperty(FIELD_GROUPING_FIELDS)
        public abstract Builder groupingFields(Set<String> groupingFields);

        @JsonProperty(FIELD_DISTINCTION_FIELDS)
        public abstract Builder distinctionFields(Set<String> distinctionFields);

        @JsonProperty(FIELD_COMMENT)
        public abstract Builder comment(String comment);

        @JsonProperty(FIELD_SEARCH_QUERY)
        public abstract Builder searchQuery(String searchQuery);

        @JsonProperty(FIELD_REPEAT_NOTIFICATIONS)
        public abstract Builder repeatNotifications(boolean repeatNotifications);

        @JsonProperty(FIELD_SEARCH_WITHIN_MS)
        public abstract Builder searchWithinMs(long searchWithinMs);

        public abstract AggregationCountProcessorConfig build();
    }

    @Override
    public ValidationResult validate() {
        ValidationResult validationResult = new ValidationResult();

        if (searchWithinMs() <= 0) {
            validationResult.addError(FIELD_SEARCH_WITHIN_MS,
                    "Aggregation Count Alert Condition search_within_ms must be greater than 0.");
        }
        if(stream() == null || stream().isEmpty()) {
            validationResult.addError(FIELD_STREAM, "Stream is mandatory");
        }
        if(thresholdType() == null || thresholdType().isEmpty()) {
            validationResult.addError(FIELD_THRESHOLD_TYPE, "Threshold type is mandatory");
        }
        if(threshold() < 0) {
            validationResult.addError(FIELD_THRESHOLD, "Threshold must be greater than 0.");
        }
        if(gracePeriod() < 0) {
            validationResult.addError(FIELD_GRACE_PERIOD, "Grace period must be greater than 0.");
        }
        if(messageBacklog() < 0) {
            validationResult.addError(FIELD_MESSAGE_BACKLOG, "Message backog must be greater than 0.");
        }
        return validationResult;
    }

    @Override
    public EventProcessorConfigEntity toContentPackEntity(EntityDescriptorIds entityDescriptorIds) {
        return AggregationCountProcessorConfigEntity.builder()
                .stream(ValueReference.of(stream()))
                .thresholdType(ValueReference.of(thresholdType()))
                .threshold(threshold())
                .timeRange((int) searchWithinMs()/(60*1000))
                .gracePeriod(gracePeriod())
                .messageBacklog(messageBacklog())
                .groupingFields(groupingFields())
                .distinctionFields(distinctionFields())
                .comment(ValueReference.of(comment()))
                .searchQuery(ValueReference.of(searchQuery()))
                .repeatNotifications(repeatNotifications())
                .build();
    }

    @Override
    public void resolveNativeEntity(EntityDescriptor entityDescriptor, MutableGraph<EntityDescriptor> mutableGraph) {

            final EntityDescriptor depStream = EntityDescriptor.builder()
                    .id(ModelId.of(stream()))
                    .type(ModelTypes.STREAM_V1)
                    .build();
            mutableGraph.putEdge(entityDescriptor, depStream);
    }
}
