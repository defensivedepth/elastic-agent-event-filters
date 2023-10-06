# Requires:
#  - yq
#  - jq
#  - pcregrep

extract_patterns() {
    TARGETFIELD=$1
    CONDITION=$2
    pcregrep -o1 -o3 --om-separator="~" "<$TARGETFIELD condition=\"$CONDITION\">(.*)<\/$TARGETFIELD>( <!--(.*)-->)?" process_create.temp | while read -r LINE ; do
        #printf "\nProcessing $LINE\n"
        ID=$RANDOM

        PATTERN=$(echo $LINE | cut -d "~" -f 1)
        CONTEXT=$(echo $LINE | cut -d "~" -f 2 | tr -d "'")


        printf '%s\n'\
            "$TARGETFIELD-$ID:"\
            "  ID: $ID"\
            "  TargetField: '$TARGETFIELD'"\
            "  Condition: '$CONDITION'"\
            "  Pattern: '$PATTERN'"\
            "  Context: '$CONTEXT'"\
            "  Source: 'github.com/Neo23x0/sysmon-config'" >> process-filters.yaml    
    done
}

data_cleanup () {
    case $1 in

    "CommandLine")
        ECSTARGETFIELD="process.command_line"
        ;;

    "Image")
        ECSTARGETFIELD="process.executable"
        ;;

    "IntegrityLevel")
        ECSTARGETFIELD="process.executable"
        ;;

    "ParentCommandLine")
        ECSTARGETFIELD="process.parent.command_line"
        ;;

    "ParentImage")
        ECSTARGETFIELD="process.parent.process.executable"
        ;;

    "is")
        ECSCONDITION="include"
        ;;

    "begin with")
        ECSCONDITION="include"
        PATTERN="${PATTERN}*"
        ;;
    *)
        echo -n "unknown"
        echo $1
        ;;
    esac
    
}

generate_json () {
    while read -r RAWJSON
    do       
        PATTERN=$(jq -r '.Pattern' <<< $RAWJSON)
        FILTERNAME="Process-$(jq -r '.ID' <<< $RAWJSON)"
        FILTERCONTEXT=$(jq -r '.Context' <<< $RAWJSON)
        data_cleanup "$(jq -r '.TargetField' <<< $RAWJSON)"
        data_cleanup "$(jq -r '.Condition' <<< $RAWJSON)"

        JSON_STRING=$( jq -c -n \
                        --arg NAME $FILTERNAME \
                        --arg PATTERN "$PATTERN" \
                        --arg TARGETFIELD $ECSTARGETFIELD \
                        --arg CONTEXT "$FILTERCONTEXT" \
                        '{"comments":[],"description":"","entries":[{"field":$TARGETFIELD,"operator":"included","type":"match","value":$PATTERN},{"field":"event.dataset","operator":"included","type":"match","value":"endpoint.events.process"}],"list_id":"endpoint_event_filters","name":$NAME,"description":$CONTEXT,"namespace_type":"agnostic","tags":["policy:all"],"type":"simple","os_types":["windows"]}'
                        )

        printf "\n\n$JSON_STRING\n\n"

        echo $JSON_STRING >> converted-filters_SO.json

    done < <( yq -o=json -I=0 '.[]' process-filters.yaml)
}


# Execution Starts here
# First, extract process filter section
pcregrep -M -o1 '(?s)<ProcessCreate onmatch="exclude">(.*)<\/ProcessCreate>' sysmonconfig-export.xml > process_create.temp


# Next, extract filters
printf "=== Extracting Filters ===\n"
set -- Image ParentImage CommandLine ParentCommandLine is contains "begin with" "ends with"
for set1; do
    shift
    for set2; do
        extract_patterns "$set1" "$set2"
        printf "Extracting Patterns: %s - %s\n" "$set1" "$set2"
    done
done

EXTRACTEDFILTERCOUNT=$(yq '. | length' process-filters.yaml)
printf "=== Finished Extracting Filters ==="
printf "\n\nTotal Extracted Filters: $EXTRACTEDFILTERCOUNT\n\n"

# Next, generate JSON from filters
generate_json

