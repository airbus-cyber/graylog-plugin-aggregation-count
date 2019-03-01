package com.airbus_cyber_security.graylog;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

import javax.annotation.Nullable;
import javax.inject.Inject;

import org.graylog2.alerts.AbstractAlertCondition;
import org.graylog2.alerts.types.MessageCountAlertCondition;
import org.graylog2.indexer.IndexSetRegistry;
import org.graylog2.indexer.indices.Indices;
import org.graylog2.indexer.results.ResultMessage;
import org.graylog2.indexer.results.SearchResult;
import org.graylog2.indexer.results.TermsResult;
import org.graylog2.indexer.searches.Searches;
import org.graylog2.indexer.searches.Sorting;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.Tools;
import org.graylog2.plugin.alarms.AlertCondition;
import org.graylog2.plugin.configuration.ConfigurationRequest;
import org.graylog2.plugin.configuration.fields.ConfigurationField;
import org.graylog2.plugin.configuration.fields.DropdownField;
import org.graylog2.plugin.configuration.fields.ListField;
import org.graylog2.plugin.configuration.fields.NumberField;
import org.graylog2.plugin.configuration.fields.TextField;
import org.graylog2.plugin.indexer.searches.timeranges.AbsoluteRange;
import org.graylog2.plugin.indexer.searches.timeranges.InvalidRangeParametersException;
import org.graylog2.plugin.indexer.searches.timeranges.RelativeRange;
import org.graylog2.plugin.streams.Stream;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Lists;
import com.google.inject.assistedinject.Assisted;
import com.google.inject.assistedinject.AssistedInject;

public class AggregationCount extends AbstractAlertCondition {
    private static final Logger LOG = LoggerFactory.getLogger(AggregationCount.class);

    private static final String FIELD_GROUPING = "grouping_fields";
    private static final String FIELD_TIME = "time";
    private static final String FIELD_THRESHOLD_TYPE = "threshold_type";
    private static final String FIELD_THRESHOLD = "threshold";
    private static final String FIELD_DISTINCTION = "distinction_fields";
    private static final String FIELD_COMMENT = "comment";
    
    

    enum ThresholdType {

        MORE("more than"),
        LESS("less than");

        private final String description;

        ThresholdType(String description) {
            this.description = description;
        }

        public String getDescription() {
            return description;
        }
    }
    
    private final Searches searches;
	private final List<String> fields;
    private final int time;
    private final ThresholdType thresholdType;
    private final int threshold;
    private final String query;
    
    private final List<String> aggregatesFields;
    private final ThresholdType aggregatesThresholdType;
    private final int aggregatesThreshold;
    private final List<String> distinctionFields;

    private final MessageCountAlertCondition msgCountAlertCondition;

    
    public interface Factory extends AlertCondition.Factory {
        @Override
        AggregationCount create(Stream stream,
                                               @Assisted("id") String id,
                                               DateTime createdAt,
                                               @Assisted("userid") String creatorUserId,
                                               Map<String, Object> parameters,
                                               @Assisted("title") @Nullable String title);

        @Override
        Config config();

        @Override
        Descriptor descriptor();
    }

    public static class Config implements AlertCondition.Config {
        private final Indices indices;
        private final IndexSetRegistry indexSetRegistry;

        @Inject
        public Config(Indices indices, IndexSetRegistry indexSetRegistry) {
        	this.indices = indices;
        	this.indexSetRegistry = indexSetRegistry;
        }

    	@Override
        public ConfigurationRequest getRequestedConfiguration() {
        	final String[] writeIndexWildcards = indexSetRegistry.getIndexWildcards();
        	HashSet<String> listFields = new HashSet <String>();
            listFields.addAll(indices.getAllMessageFields(writeIndexWildcards));
            /* Fielddata is disabled on fields message and full_message */
            listFields.remove("message");
            listFields.remove("full_message");
            Map<String, String> mapFields = listFields.stream().collect(Collectors.toMap(x -> x, x -> x));
            Map<String, String> treeMapFields = mapFields.entrySet().stream().sorted(Map.Entry.comparingByValue())
    		.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue,(e1, e2) -> e1, LinkedHashMap::new));

            final ConfigurationRequest configurationRequest = ConfigurationRequest.createWithFields(
                    new ListField(FIELD_GROUPING, "Grouping Fields", 
                    		Collections.emptyList(), 
                    		treeMapFields,
                    		"Fields that should be checked to count messages with the same values", 
                    		ConfigurationField.Optional.OPTIONAL,
                    		ListField.Attribute.ALLOW_CREATE),
                    new NumberField(FIELD_TIME, "Time Range", 5, 
                    		"Evaluate the condition for all messages received in the given number of minutes", 
                    		ConfigurationField.Optional.NOT_OPTIONAL),
                    new DropdownField(
                            FIELD_THRESHOLD_TYPE,
                            "Threshold Type",
                            ThresholdType.MORE.toString(),
                            Arrays.stream(ThresholdType.values()).collect(Collectors.toMap(Enum::toString, ThresholdType::getDescription)),
                            "Select condition to trigger alert: when there are more or less messages with the same value of grouping fields "
                            + "and with distinct values of distinction fields than the threshold",
                            ConfigurationField.Optional.NOT_OPTIONAL),
                    new NumberField(FIELD_THRESHOLD, "Threshold", 0.0, 
                    		"Value which triggers an alert if crossed", 
                    		ConfigurationField.Optional.NOT_OPTIONAL),
                    new ListField(FIELD_DISTINCTION, "Distinction Fields", 
                    		Collections.emptyList(), 
                    		treeMapFields,
                    		"Fields that should be checked to count messages with distinct values", 
                    		ConfigurationField.Optional.OPTIONAL,
                    		ListField.Attribute.ALLOW_CREATE),
            		new TextField(FIELD_COMMENT,
                            "Comment",
                            "",
                            "Comment about the configuration",
                            ConfigurationField.Optional.OPTIONAL)
            );
            configurationRequest.addFields(AbstractAlertCondition.getDefaultConfigurationFields());
            return configurationRequest;
        }
    }

    public static class Descriptor extends AlertCondition.Descriptor {
        public Descriptor() {
            super(
                "Aggregation Count Alert Condition",
                "https://www.airbus-cyber-security.com",
                "This condition is triggered when the number of messages with the same value of some message fields "
                + "and with distinct values of other messages fields is higher/lower than a defined threshold in a given time range."
            );
        }
    }

	@SuppressWarnings("unchecked")
	@AssistedInject
    public AggregationCount(Searches searches,
                                           @Assisted Stream stream,
                                           @Nullable @Assisted("id") String id,
                                           @Assisted DateTime createdAt,
                                           @Assisted("userid") String creatorUserId,
                                           @Assisted Map<String, Object> parameters,
                                           @Assisted("title") @Nullable String title) {
        super(stream, id, AggregationCount.class.getCanonicalName(), createdAt, creatorUserId, parameters, title);    
        this.searches = searches;
        this.time = Tools.getNumber(parameters.get(FIELD_TIME), 5).intValue();
        
        this.aggregatesFields = (List<String>) parameters.getOrDefault(FIELD_GROUPING, new ArrayList<String>());
       
        this.fields = new ArrayList<>();
        this.fields.addAll(aggregatesFields);    
        
        this.distinctionFields = (List<String>) parameters.getOrDefault(FIELD_DISTINCTION,Collections.emptyList());
        if(!distinctionFields.isEmpty()) {
        	this.fields.addAll(distinctionFields);
        	
        	this.thresholdType = ThresholdType.MORE;
        	this.threshold = 0;
        	this.aggregatesThresholdType = ThresholdType.valueOf((String) parameters.get(FIELD_THRESHOLD_TYPE));
            this.aggregatesThreshold = Tools.getNumber(parameters.get(FIELD_THRESHOLD), 0).intValue();   
        }else {
        	this.thresholdType = ThresholdType.valueOf((String) parameters.get(FIELD_THRESHOLD_TYPE));
        	this.threshold = Tools.getNumber(parameters.get(FIELD_THRESHOLD), 0).intValue();    
        	this.aggregatesThresholdType = ThresholdType.MORE;
        	this.aggregatesThreshold = 0;
        }
        this.query = (String) parameters.getOrDefault(CK_QUERY, CK_QUERY_DEFAULT_VALUE);
        msgCountAlertCondition = new MessageCountAlertCondition(searches, stream, id, createdAt, creatorUserId, parameters, title);
    }

    @Override
    public String getDescription() {
        return "time: " + time
                + ", threshold_type: " + thresholdType.toString().toLowerCase(Locale.ENGLISH)
                + ", threshold: " + threshold
                + ", grace: " + grace
                + ", fields: " + String.join(" ",fields)
                + ", aggregates_threshold_type: " + aggregatesThresholdType.toString().toLowerCase(Locale.ENGLISH)
                + ", aggregates_threshold: " + aggregatesThreshold
                + ", aggregates_fields: " + String.join(" ",aggregatesFields)
                + ", repeat notifications: " + repeatNotifications;
    }
        
    private boolean isTriggered(ThresholdType thresholdType, int threshold, long count) {
    	return (((thresholdType == ThresholdType.MORE) && (count > threshold)) || 
    			((thresholdType == ThresholdType.LESS) && (count < threshold)));
    }
    
    private void addSearchMessages(List<MessageSummary> summaries, String searchQuery, String filter, AbsoluteRange range) {
    	final SearchResult backlogResult = searches.search(searchQuery, filter,
				range, getBacklog(), 0, new Sorting(Message.FIELD_TIMESTAMP, Sorting.Direction.DESC));
		for (ResultMessage resultMessage : backlogResult.getResults()) {
			if (summaries.size() >= getBacklog()) break;
			summaries.add(new MessageSummary(resultMessage.getIndex(), resultMessage.getMessage()));
		}
    }
    
    private String buildSearchQuery(String firstField, List<String> nextFields, String matchedFieldValue) {
		for (String field : nextFields) {
			matchedFieldValue = matchedFieldValue.replaceFirst(" - ", "\" AND " + field + ": \"");
		}
		return (query + " AND " + firstField + ": \"" + matchedFieldValue + "\"");
    }
    
    private String getResultDescription(int aggregatesNumber, long messagesNumber) {
    	    	
    	if(!aggregatesFields.isEmpty() && !distinctionFields.isEmpty()) {
    		
    		return "Stream had " + aggregatesNumber + " messages in the last " + time + " minutes with trigger condition " 
    				+ aggregatesThresholdType.toString().toLowerCase(Locale.ENGLISH) + " than " + aggregatesThreshold 
    				+ " messages with the same value of the fields " + String.join(", ",aggregatesFields)
    				+ ", and with distinct values of the fields " + String.join(", ",distinctionFields)
    				+ ". (Current grace time: " + grace + " minutes)";
    	
    	}else if(!aggregatesFields.isEmpty() && distinctionFields.isEmpty()){
    	
    		return "Stream had " + messagesNumber + " messages in the last " + time + " minutes with trigger condition "
    				+ thresholdType.toString().toLowerCase(Locale.ENGLISH) + " than " + threshold 
    				+ " messages with the same value of the fields " + String.join(", ",aggregatesFields) + 
    				". (Current grace time: " + grace + " minutes)";
    	
    	}else if(aggregatesFields.isEmpty() && !distinctionFields.isEmpty()){
    	
    		return "Stream had " + aggregatesNumber + " messages in the last " + time + " minutes with trigger condition " 
    				+ aggregatesThresholdType.toString().toLowerCase(Locale.ENGLISH) + " than " + aggregatesThreshold 
    				+ " messages with distinct values of the fields " + String.join(", ",distinctionFields)
    				+ ". (Current grace time: " + grace + " minutes)";
    	
    	}else {
    	
    		return "Stream had " + messagesNumber + " messages in the last " + time + " minutes with trigger condition "
    				+ thresholdType.toString().toLowerCase(Locale.ENGLISH) + " than " + threshold 
    				+ "messages. (Current grace time: " + grace + " minutes)";
    	
    	}
    	
    }
    
    private boolean getListMessageSummary (List<MessageSummary> summaries, Map<String, List<String>> matchedTerms,
    		String firstField, List<String> nextFields, final AbsoluteRange range, String filter) {
    	Boolean ruleTriggered = false;
    	Map<String, Long> frequenciesFields = new HashMap<>();
		for (Map.Entry<String, List<String>> matchedTerm : matchedTerms.entrySet()) {
			String valuesAgregates = matchedTerm.getKey();
			List<String> listAggregates = matchedTerm.getValue();
			
			if(!frequenciesFields.containsKey(valuesAgregates)) {
				frequenciesFields.put(valuesAgregates, Long.valueOf(listAggregates.size()));
				LOG.debug(listAggregates.size()+" aggregates for values "+valuesAgregates);
			}
		}
		
		for (Map.Entry<String, Long> frequencyField : frequenciesFields.entrySet()) { 				
			if (isTriggered(aggregatesThresholdType, aggregatesThreshold, frequencyField.getValue())) {
				ruleTriggered=true;

				for (String matchedFieldValue : matchedTerms.get(frequencyField.getKey())) {
					String searchQuery = buildSearchQuery(firstField, nextFields, matchedFieldValue);

					LOG.debug("Search: "+searchQuery);

					addSearchMessages(summaries, searchQuery, filter, range);
					
					LOG.debug(String.valueOf(summaries.size()+" Messages in CheckResult"));
				}
			}
		}
		return ruleTriggered;
    }
    
    /**
     * @param matchedTerms non-null list of matched terms to return
     * @param termsResult 
     * @return return the rule count
     **/
    private long getMatchedTerm(Map<String, List<String>> matchedTerms, TermsResult termsResult) {
    	long ruleCount = 0;
		boolean isFirstTriggered = true;
		for (Map.Entry<String, Long> term : termsResult.getTerms().entrySet()) {

			String matchedFieldValue = term.getKey();
			Long count = term.getValue();

			if (isTriggered(thresholdType, threshold, count)) {
				String [] valuesFields = matchedFieldValue.split(" - ");
				int i=0;
				StringBuilder bldStringValuesAgregates = new StringBuilder("Agregates:");
				for (String field : fields) {
					if(aggregatesFields.contains(field) && i<valuesFields.length) {
						bldStringValuesAgregates.append(valuesFields[i]);
					}
					i++;
				}
				String valuesAgregates = bldStringValuesAgregates.toString();

				if(matchedTerms.containsKey(valuesAgregates)) {
					matchedTerms.get(valuesAgregates).add(matchedFieldValue);
				}else {
					matchedTerms.put(valuesAgregates, Lists.newArrayList(matchedFieldValue));
				}
				
				if(isFirstTriggered) {
					ruleCount = count;
					isFirstTriggered = false;
				}
			}
		}
		return ruleCount;
    }
        
    
    /**
     * Check if the condition is triggered
     * 
     * This condition is triggered when the number of messages with the same value of some message fields 
     * and with distinct values of other messages fields is higher/lower than a defined threshold in a given time range.
     * 
     * @return CheckResult 
     * 					Result Description and list of messages that satisfy the conditions
     */
    private CheckResult runCheckAggregationField() { 
    	try {
    		/* Create an absolute range from the relative range */
    		final RelativeRange relativeRange = RelativeRange.create(time * 60);
    		final AbsoluteRange range = AbsoluteRange.create(relativeRange.getFrom(), relativeRange.getTo());
    		if (range == null) {
    			return null;
    		}

    		final String filter = "streams:" + stream.getId();
    		Integer backlogSize = getBacklog();
    		boolean backlogEnabled = false;
    		int searchLimit = 100;
    		if(backlogSize != null && backlogSize > 0) {
    			backlogEnabled = true;
    			searchLimit = backlogSize;
    		}
    		String firstField = fields.get(0);
    		List<String> nextFields = new ArrayList<>(fields);
    		nextFields.remove(0);
    			
    		/* Get the matched term */
    		TermsResult result = searches.terms(firstField, nextFields, searchLimit, query, filter, range, Sorting.Direction.DESC);
    		Map<String, List<String>> matchedTerms = new HashMap<>();
    		long  ruleCount = getMatchedTerm(matchedTerms, result);
    		
    		/* Get the list of summary messages */
    		List<MessageSummary> summaries = Lists.newArrayListWithCapacity(searchLimit);
    		boolean ruleTriggered=false;
    		if (!backlogEnabled) {
    			summaries = Collections.emptyList();
    		} else {
    			ruleTriggered = getListMessageSummary(summaries, matchedTerms, firstField, nextFields, range, filter);
    		} 

    		/* If rule triggered return the check result */
    		if (ruleTriggered) {
    			return new CheckResult(true, this, getResultDescription(summaries.size(), ruleCount), Tools.nowUTC(), summaries);
    		}

    		return new NegativeCheckResult();
    	} catch (InvalidRangeParametersException e) {
    		LOG.error("Invalid timerange.", e);
    		return null;
    	}
    }
    
    @Override
    public CheckResult runCheck() {       
    	if(fields == null || fields.isEmpty()) {
    		return msgCountAlertCondition.runCheck();
    	}else {
    		return runCheckAggregationField();
    	}
    }

}
