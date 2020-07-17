package com.airbus_cyber_security.graylog.events.contentpack.entities;

import com.airbus_cyber_security.graylog.events.processor.aggregation.AggregationCountProcessorConfig;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.google.auto.value.AutoValue;
import org.graylog.events.contentpack.entities.EventProcessorConfigEntity;
import org.graylog.events.processor.EventProcessorConfig;
import org.graylog2.contentpacks.model.entities.EntityDescriptor;
import org.graylog2.contentpacks.model.entities.references.ValueReference;

import java.util.Map;
import java.util.Set;

@AutoValue
@JsonTypeName(AggregationCountProcessorConfigEntity.TYPE_NAME)
@JsonDeserialize(builder = AggregationCountProcessorConfigEntity.Builder.class)
public abstract class AggregationCountProcessorConfigEntity implements EventProcessorConfigEntity {

    public static final String TYPE_NAME = "aggregation-count";

    private static final String FIELD_STREAM = "stream";
    private static final String FIELD_THRESHOLD_TYPE = "threshold_type";
    private static final String FIELD_THRESHOLD = "threshold";
    private static final String FIELD_TIME_RANGE = "time_range";
    private static final String FIELD_GRACE_PERIOD = "grace_period";
    private static final String FIELD_MESSAGE_BACKLOG = "message_backlog";
    private static final String FIELD_GROUPING_FIELDS = "grouping_fields";
    private static final String FIELD_DISTINCTION_FIELDS = "distinction_fields";
    private static final String FIELD_COMMENT = "comment";
    private static final String FIELD_SEARCH_QUERY = "search_query";
    private static final String FIELD_REPEAT_NOTIFICATIONS = "repeat_notifications";

    @JsonProperty(FIELD_STREAM)
    public abstract ValueReference stream();

    @JsonProperty(FIELD_THRESHOLD_TYPE)
    public abstract ValueReference thresholdType();

    @JsonProperty(FIELD_THRESHOLD)
    public abstract int threshold();

    @JsonProperty(FIELD_TIME_RANGE)
    public abstract int timeRange();

    @JsonProperty(FIELD_GRACE_PERIOD)
    public abstract int gracePeriod();

    @JsonProperty(FIELD_MESSAGE_BACKLOG)
    public abstract int messageBacklog();

    @JsonProperty(FIELD_GROUPING_FIELDS)
    public abstract Set<String> groupingFields();

    @JsonProperty(FIELD_DISTINCTION_FIELDS)
    public abstract Set<String> distinctionFields();

    @JsonProperty(FIELD_COMMENT)
    public abstract ValueReference comment();

    @JsonProperty(FIELD_SEARCH_QUERY)
    public abstract ValueReference searchQuery();

    @JsonProperty(FIELD_REPEAT_NOTIFICATIONS)
    public abstract boolean repeatNotifications();

    public static Builder builder() {
        return Builder.create();
    }

    public abstract Builder toBuilder();

    @AutoValue.Builder
    public static abstract class Builder implements EventProcessorConfigEntity.Builder<Builder> {
        @JsonCreator
        public static Builder create() {
            return new AutoValue_AggregationCountProcessorConfigEntity.Builder()
                    .type(TYPE_NAME);
        }

        @JsonProperty(FIELD_STREAM)
        public abstract Builder stream(ValueReference stream);

        @JsonProperty(FIELD_THRESHOLD_TYPE)
        public abstract Builder thresholdType(ValueReference thresholdType);

        @JsonProperty(FIELD_THRESHOLD)
        public abstract Builder threshold(int threshold);

        @JsonProperty(FIELD_TIME_RANGE)
        public abstract Builder timeRange(int timeRange);

        @JsonProperty(FIELD_GRACE_PERIOD)
        public abstract Builder gracePeriod(int gracePeriod);

        @JsonProperty(FIELD_MESSAGE_BACKLOG)
        public abstract Builder messageBacklog(int messageBacklog);

        @JsonProperty(FIELD_GROUPING_FIELDS)
        public abstract Builder groupingFields(Set<String> groupingFields);

        @JsonProperty(FIELD_DISTINCTION_FIELDS)
        public abstract Builder distinctionFields(Set<String> distinctionFields);

        @JsonProperty(FIELD_COMMENT)
        public abstract Builder comment(ValueReference comment);

        @JsonProperty(FIELD_SEARCH_QUERY)
        public abstract Builder searchQuery(ValueReference searchQuery);

        @JsonProperty(FIELD_REPEAT_NOTIFICATIONS)
        public abstract Builder repeatNotifications(boolean repeatNotifications);

        public abstract AggregationCountProcessorConfigEntity build();
    }

    @Override
    public EventProcessorConfig toNativeEntity(Map<String, ValueReference> parameters, Map<EntityDescriptor, Object> nativeEntities) {
        return AggregationCountProcessorConfig.builder()
                .stream(stream().asString(parameters))
                .thresholdType(thresholdType().asString(parameters))
                .threshold(threshold())
                .searchWithinMs(timeRange()*60*1000)
                .executeEveryMs(gracePeriod()*60*1000)
                .messageBacklog(messageBacklog())
                .groupingFields(groupingFields())
                .distinctionFields(distinctionFields())
                .comment(comment().asString(parameters))
                .searchQuery(searchQuery().asString(parameters))
                .repeatNotifications(repeatNotifications())
                .build();
    }
}
