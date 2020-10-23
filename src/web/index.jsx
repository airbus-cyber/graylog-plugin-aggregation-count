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

import { PluginManifest, PluginStore } from 'graylog-web-plugin/plugin';

import AggregationCountFormContainer from "./components/event-definitions/event-definition-types/AggregationCountFormContainer";
import AggregationCountSummary from "./components/event-definitions/event-definition-types/AggregationCountSummary";

PluginStore.register(new PluginManifest({}, {
    eventDefinitionTypes: [
        {
            type: 'aggregation-count',
            displayName: 'Aggregation Count Alert Condition',
            sortOrder: 2, // Sort before conditions working on events
            description: 'This condition is triggered when the number of messages with the same value of some message fields '
                + 'and with distinct values of other messages fields is higher/lower than a defined threshold in a given time range.',
            formComponent: AggregationCountFormContainer,
            summaryComponent: AggregationCountSummary,
            defaultConfig: {
              stream: '',
              threshold_type: 'more than',
              threshold: '0',
              search_within_ms: 60*1000,
              execute_every_ms: 60*1000,
              grouping_fields: [],
              distinction_fields: [],
              comment: '',
              search_query: '*',
            },
        },
    ],
}));