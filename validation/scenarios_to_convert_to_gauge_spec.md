# End-to-end test scenarios

Ideally these validation scenarios should be scripted and run from an automatic end-to-end testing framework.
So that they can be included in continuous integration.
For the time being, they must be run by hand.

## Execution Environment
* docker-compose
* the compiled jar for this plugin (graylog-plugin-aggregation-count)

## Scenarios
### Plugin should not fail on receiving a message
* start the graylog docker-compose
  ```bash
  docker-compose up
  ```
* wait till you see the log "Graylog server up and running."
* log into http://127.0.0.1:9000/ as admin:admin
* in tab System/Inputs, launch a new global tcp input
* in tab Alerts, go to Event definitions
* create a new "Aggregation Count Alert Condition" with fields
  * Stream: All messages
  * Threshold type: more than
* send a message
  ```bash
  logger --server 127.0.0.1 --port 514 --tcp --tag test 'This is just an arbitrary test message...'
  ```
* Wait some time (less than a minute)
* There shouldn't be any error in the Graylog logs, such as:
  ```
   ERROR: org.graylog.events.processor.EventProcessorEngine - Caught an unhandled exception while executing event processor <aggregation-count/Airbus Aggregation/5f0ed2a5915abf0012c76190> - Make sure to modify the event processor to throw only EventProcessorExecutionException so we get more context!
   java.lang.NullPointerException: null
  ```

### Plugin should display alerts when triggered
* start the graylog docker-compose
  ```bash
  docker-compose up
  ```
* wait till you see the log "Graylog server up and running."
* log into http://127.0.0.1:9000/ as admin:admin
* in tab System/Inputs, launch a new global tcp input
* in tab Alerts, go to Event definitions
* create a new "Aggregation Count Alert Condition" with fields
  * Stream: All messages
  * Threshold type: more than
  * Message Backlog: 1
* send a message
  ```bash
  logger --server 127.0.0.1 --port 514 --tcp --tag test 'This is just an arbitrary test message...'
  ```
* Wait some time (less than a minute)
* go to "Alerts & Events" and check there is at least an alert
