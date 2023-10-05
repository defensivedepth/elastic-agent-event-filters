#!/bin/bash
file="converted-filters_SO.json"
while IFS= read -r line
do
    #printf '%s\n' "$line"
    curl -K /opt/so/conf/elasticsearch/curl.config -L -X POST "localhost:5601/api/exception_lists/items" -H 'kbn-xsrf: true' -H 'Content-Type: application/json' -d "$line"
done <"$file"