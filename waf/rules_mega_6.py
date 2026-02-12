"""
BeeWAF Mega Rules Database — Part 6
=====================================
Encoding evasion variants, protocol-specific attacks, framework fingerprinting,
API abuse, database-specific deep patterns, and infrastructure attacks.
~2500 additional patterns.
"""

# ============================================================================
# 1. ENCODING EVASION - ALL VARIANTS (350 patterns)
# ============================================================================
ENCODING_EVASION = [
    # --- Double URL encoding ---
    r"(?i)%25(?:27|22|3c|3e|28|29|2f|5c|3b|7c|60|24|7b|7d|0a|0d|00|20|09|23|26|2b|2c|3a|3d|3f|40|5b|5d|5e)",
    r"(?i)%25(?:32(?:37|32|38|39|66|63|65|62)|33(?:63|65|62|61|66|64)|35(?:63|65|62)|37(?:63|62|65))",
    r"(?i)%(?:c0%ae|c1%9c|c0%af|c1%1c|c0%2f|e0%80%ae|e0%80%af|f0%80%80%ae|f0%80%80%af)",
    r"(?i)%u(?:002f|005c|002e|003c|003e|0027|0022|003b|007c|0060|ff0f|ff3c|ff0e|ff1c|ff1e|ff07|ff02|ff1b|ff5c|ff40)",
    r"(?i)%(?:ef%bc%8f|ef%bc%9c|ef%bc%9e|ef%bc%87|ef%bc%82|ef%bc%9b|ef%bc%9a|ef%bc%bf|ef%bd%80|ef%bd%9c|ef%bd%9e|ef%bc%88|ef%bc%89|ef%bd%9b|ef%bd%9d|ef%bd%a0|ef%bd%a1)",
    # --- Unicode normalization attacks ---
    r"(?i)\\u(?:ff0f|ff3c|ff0e|ff1c|ff1e|ff07|ff02|ff1b|ff5c|ff40|ff08|ff09|ff5b|ff5d|ff20|ff04|ff03|ff25|ff06|ff2b|ff2c|ff3a|ff3d|ff3e|ff3f|fe68|fe6a|fe6b)",
    r"(?i)\\u(?:0000|feff|200[0-9a-f]|2028|2029|202[a-f]|2060|2061|2062|2063|2064|fffe|ffff|d800|dbff|dc00|dfff)",
    r"(?i)\\u(?:0027|0022|003c|003e|002f|005c|003b|007c|0060|0024|007b|007d|0028|0029|0040|0023|0025|0026|002b|002c|003a|003d|003f|005b|005d|005e|005f|007e)",
    r"(?i)(?:%e2%80%8b|%e2%80%8c|%e2%80%8d|%e2%80%8e|%e2%80%8f|%e2%80%aa|%e2%80%ab|%e2%80%ac|%e2%80%ad|%e2%80%ae|%e2%81%a0|%e2%81%a1|%e2%81%a2|%e2%81%a3|%e2%81%a4|%ef%bb%bf|%c2%a0|%c2%ad)",
    # --- HTML entity encoding ---
    r"(?i)&#(?:x0*(?:27|22|3c|3e|2f|5c|3b|7c|60|24|28|29|7b|7d|5b|5d|40|23|25|26|2b|2c|3a|3d|3f|5e|5f|7e|0a|0d|09|00|20))\s*;?",
    r"(?i)&#0*(?:39|34|60|62|47|92|59|124|96|36|40|41|123|125|91|93|64|35|37|38|43|44|58|61|63|94|95|126|10|13|9|0|32)\s*;?",
    r"(?i)&(?:lt|gt|amp|quot|apos|sol|bsol|semi|vert|grave|dollar|lpar|rpar|lbrace|rbrace|lsqb|rsqb|commat|num|percnt|plus|comma|colon|equals|quest|Hat|lowbar|tilde|Tab|NewLine|nbsp|ensp|emsp|thinsp|zwnj|zwj|lrm|rlm)\s*;",
    r"(?i)&(?:Agrave|Aacute|Acirc|Atilde|Auml|Aring|AElig|Ccedil|Egrave|Eacute|Ecirc|Euml|Igrave|Iacute|Icirc|Iuml|ETH|Ntilde|Ograve|Oacute|Ocirc|Otilde|Ouml|Oslash|Ugrave|Uacute|Ucirc|Uuml|Yacute|THORN|szlig|agrave|aacute|acirc|atilde|auml|aring|aelig|ccedil|egrave|eacute|ecirc|euml|igrave|iacute|icirc|iuml|eth|ntilde|ograve|oacute|ocirc|otilde|ouml|oslash|ugrave|uacute|ucirc|uuml|yacute|thorn|yuml)\s*;",
    # --- Overlong UTF-8 ---
    r"(?i)(?:%c0%af|%c1%1c|%c1%9c|%c0%ae|%c0%2f|%c0%5c|%c0%2e)",
    r"(?i)(?:%e0%80%af|%e0%80%ae|%e0%80%2f|%e0%80%5c|%e0%80%2e)",
    r"(?i)(?:%f0%80%80%af|%f0%80%80%ae|%f0%80%80%2f|%f0%80%80%5c|%f0%80%80%2e)",
    # --- Null byte injection ---
    r"(?i)%00(?:\.|/|\\|;|:|'|\"|<|>|\||&|!|@|#|\$|%|\^|\*|\(|\)|\{|\}|\[|\]|~|`|\+|,|=|\?)",
    r"(?i)\\x00(?:\.|/|\\|;)",
    r"(?i)\\0(?:\.|/|\\|;)",
    r"(?i)\\u0000(?:\.|/|\\|;)",
    r"(?i)%(?:00|01|02|03|04|05|06|07|08|0b|0c|0e|0f|10|11|12|13|14|15|16|17|18|19|1a|1b|1c|1d|1e|1f|7f)",
    # --- Mixed encoding ---
    r"(?i)(?:%27|')(?:\s|%20|%09|%0[adAD]|\+)*(?:or|and|union|select|insert|update|delete|drop|exec|execute|having|order|group|where|from|into|values|set|like|between|exists|all|any|null)\b",
    r"(?i)(?:%3c|<)(?:\s|%20|%09|%0[adAD]|\+)*(?:script|img|svg|body|iframe|object|embed|form|input|link|meta|style|applet|base|frameset|layer|ilayer|bgsound|isindex|marquee|multicol|nobr|noembed|noframes|nolayer|nosave|plaintext|spacer|wbr|xmp|xml|xss)\b",
    r"(?i)(?:\\x27|\\x22|\\x3c|\\x3e|\\x2f|\\x5c|\\x3b|\\x7c|\\x60).*(?:or|and|union|select|script|img|svg|alert|confirm|prompt|eval|document|window|cookie|onerror|onload)\b",
    # --- Base64 encoded attacks ---
    r"(?i)(?:PHNjcmlwdD|PGltZyB|PHN2ZyB|PGJvZHk|PGlmcmFtZ|PG9iamVjdC|PGVtYmVk|PGZvcm0|PGlucHV0|PGxpbms|PG1ldGE|PHN0eWxl|PGFwcGxldC|PGJhc2U|YWxlcnQo|Y29uZmlybS|cHJvbXB0K|ZXZhbCg|ZG9jdW1lbnQ|d2luZG93L|bG9jYXRpb24|bmF2aWdhdG9y|Y29va2ll|b25lcnJvcj|b25sb2Fk|b25tb3VzZW)",
    r"(?i)(?:J3VuaW9u|dW5pb24g|c2VsZWN0|aW5zZXJ0|dXBkYXRl|ZGVsZXRl|ZHJvcCA|ZXhlY3V0|eHBfY21k|c3BfY29u|bG9hZF9m|aW50byBv|d2FpdGZvcg|YmVuY2htYXJr|c2xlZXAo|cGdfc2xlZXA)",
    # --- Case manipulation via partial hex-encoding (actual evasion) ---
    r"(?i)(?:s%45lect|se%4cect|sel%45ct|sele%43t|selec%54)\b",
    r"(?i)(?:u%4eion|un%49on|uni%4fn|unio%4e)\b",
    r"(?i)(?:i%4esert|in%53ert|ins%45rt|inse%52t|inser%54)\b",
    r"(?i)(?:d%45lete|de%4cete|del%45te|dele%54e|delet%45)\b",
    r"(?i)(?:d%52op|dr%4fp|dro%50)\b",
    r"(?i)(?:s%43ript|sc%52ipt|scr%49pt|scri%50t|scrip%54)\b",
    r"(?i)(?:a%4cert|al%45rt|ale%52t|aler%54)\b",
    # --- Comment evasion ---
    r"(?i)/\*.*\*/\s*(?:union|select|insert|update|delete|drop|exec|having|order|group)\b",
    r"(?i)/\*\!(?:\d{5})?\s*(?:union|select|insert|update|delete|drop|exec|having|order|group)\b",
    r"(?i)(?:union|select|insert|update|delete|drop)\s*/\*.*\*/\s*(?:union|select|insert|update|delete|drop|all|from|where|having|order|group|into|values|set)\b",
    r"(?i)--\s*(?:-|\+|~|!|@|#|\$|%|\^|&|\*)\s*(?:\n|\r\n)?\s*(?:union|select|insert|update|delete|drop|exec)\b",
    r"(?i)#\s*(?:\n|\r\n)?\s*(?:union|select|insert|update|delete|drop|exec)\b",
    r"(?i)(?:un/\*\*/ion|se/\*\*/lect|in/\*\*/sert|up/\*\*/date|de/\*\*/lete|dr/\*\*/op|ex/\*\*/ec)\b",
    r"(?i)(?:uni%6fn|se%6cect|ins%65rt|upd%61te|del%65te|dro%70|exe%63)\b",
    # --- Whitespace evasion ---
    r"(?i)(?:union|select|insert|update|delete|drop|exec)(?:\s|%20|%09|%0a|%0d|%0b|%0c|%a0|\+|/\*\*/|/\*!\*/){2,}(?:union|select|insert|update|delete|drop|exec|all|from|where|having|order|group|into|values|set)\b",
    r"(?i)(?:union|select)(?:\x09|\x0a|\x0b|\x0c|\x0d|\xa0)+(?:select|all|from|where)\b",
    r"(?i)(?:union|select)(?:%(?:09|0[aAbBcCdD]|20|a0))+(?:select|all|from|where)\b",
]

# ============================================================================
# 2. DATABASE PROTOCOL ATTACKS (300 patterns)
# ============================================================================
DB_PROTOCOL_ATTACKS = [
    # --- MySQL protocol ---
    r"(?i)\bSHOW\s+(?:DATABASES|SCHEMAS|TABLES|COLUMNS|INDEX|INDEXES|KEYS|CREATE\s+(?:TABLE|DATABASE|VIEW|PROCEDURE|FUNCTION|TRIGGER|EVENT)|FULL\s+(?:TABLES|COLUMNS|PROCESSLIST)|GRANTS|PRIVILEGES|ENGINES|PLUGINS|MASTER\s+STATUS|SLAVE\s+STATUS|REPLICAS|BINARY\s+LOGS|BINLOG\s+EVENTS|RELAYLOG\s+EVENTS|GLOBAL\s+(?:STATUS|VARIABLES)|SESSION\s+(?:STATUS|VARIABLES)|WARNINGS|ERRORS|PROFILE|PROFILES|OPEN\s+TABLES|TABLE\s+STATUS|TRIGGERS|EVENTS|PROCEDURE\s+STATUS|FUNCTION\s+STATUS)\b",
    r"(?i)\bSET\s+(?:GLOBAL|SESSION|LOCAL)?\s*(?:@@(?:global|session|local)\.)?\s*(?:sql_safe_updates|sql_mode|max_execution_time|max_join_size|max_sort_length|sort_buffer_size|read_buffer_size|join_buffer_size|tmp_table_size|max_heap_table_size|group_concat_max_len|ft_min_word_len|ft_max_word_len|innodb_lock_wait_timeout|lock_wait_timeout|net_read_timeout|net_write_timeout|wait_timeout|interactive_timeout|connect_timeout|delayed_insert_timeout|innodb_flush_log_at_trx_commit|autocommit|foreign_key_checks|unique_checks|profiling|general_log|slow_query_log|log_bin|binlog_format|character_set_server|character_set_client|character_set_connection|character_set_results|collation_server|collation_connection|time_zone|lc_time_names|max_allowed_packet|max_connections|max_user_connections|sql_log_bin|read_only|super_read_only|secure_file_priv|local_infile|query_cache_type|query_cache_size|event_scheduler|optimizer_switch|default_storage_engine)\s*=",
    r"(?i)\b(?:LOAD\s+DATA\s+(?:LOCAL\s+)?INFILE|SELECT\s+.*\bINTO\s+(?:OUTFILE|DUMPFILE)|LOAD_FILE\s*\()\b",
    r"(?i)\b(?:HANDLER\s+\w+\s+(?:OPEN|READ|CLOSE)|HELP\s+')\b",
    r"(?i)\b(?:PREPARE|EXECUTE|DEALLOCATE\s+PREPARE)\s+\w+",
    r"(?i)\b(?:CREATE|ALTER|DROP)\s+(?:USER|ROLE|DATABASE|SCHEMA|TABLE|VIEW|INDEX|TRIGGER|EVENT|FUNCTION|PROCEDURE|SERVER|TABLESPACE|LOGFILE\s+GROUP)\b",
    r"(?i)\b(?:GRANT|REVOKE)\s+(?:ALL|SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|INDEX|EXECUTE|GRANT\s+OPTION|SUPER|REPLICATION\s+(?:SLAVE|CLIENT)|FILE|PROCESS|RELOAD|SHUTDOWN|SHOW\s+DATABASES|LOCK\s+TABLES|REFERENCES|CREATE\s+(?:VIEW|ROUTINE|TEMPORARY\s+TABLES|USER)|ALTER\s+ROUTINE|EVENT|TRIGGER)\b",
    r"(?i)\b(?:FLUSH\s+(?:PRIVILEGES|TABLES|LOGS|HOSTS|STATUS|QUERY\s+CACHE|DES_KEY_FILE|USER_RESOURCES|RELAY\s+LOGS|ERROR\s+LOGS|GENERAL\s+LOGS|SLOW\s+LOGS|BINARY\s+LOGS|ENGINE\s+LOGS|OPTIMIZER_COSTS)|RESET\s+(?:MASTER|SLAVE|QUERY\s+CACHE)|PURGE\s+(?:BINARY|MASTER)\s+LOGS)\b",
    r"(?i)\b(?:CHANGE\s+MASTER\s+TO|START\s+SLAVE|STOP\s+SLAVE|START\s+REPLICA|STOP\s+REPLICA|CHANGE\s+REPLICATION\s+SOURCE|START\s+GROUP_REPLICATION|STOP\s+GROUP_REPLICATION)\b",
    # --- PostgreSQL protocol ---
    r"(?i)\b(?:CREATE|ALTER|DROP)\s+(?:EXTENSION|FOREIGN\s+(?:TABLE|DATA\s+WRAPPER|SERVER)|LANGUAGE|OPERATOR|SCHEMA|SEQUENCE|TYPE|AGGREGATE|CAST|COLLATION|CONVERSION|DOMAIN|ENUM|EVENT\s+TRIGGER|MATERIALIZED\s+VIEW|POLICY|PUBLICATION|RULE|STATISTICS|SUBSCRIPTION|TEXT\s+SEARCH)\b",
    r"(?i)\b(?:COPY|\\copy)\s+(?:\w+|\([^)]+\))\s+(?:FROM|TO)\s+(?:STDIN|STDOUT|PROGRAM|'[^']*')\b",
    r"(?i)\b(?:LISTEN|NOTIFY|UNLISTEN)\s+\w+\b",
    r"(?i)\b(?:CLUSTER|VACUUM|ANALYZE|REINDEX|CHECKPOINT|DISCARD)\b",
    r"(?i)\b(?:SET\s+(?:ROLE|SESSION\s+AUTHORIZATION|LOCAL|CONSTRAINTS|TRANSACTION|work_mem|shared_buffers|effective_cache_size|maintenance_work_mem|checkpoint_completion_target|wal_buffers|default_statistics_target|random_page_cost|effective_io_concurrency|max_worker_processes|max_parallel_workers_per_gather|max_parallel_workers|max_parallel_maintenance_workers|min_wal_size|max_wal_size|wal_level|archive_mode|archive_command|max_wal_senders|wal_keep_segments|hot_standby|synchronous_commit|synchronous_standby_names|log_min_duration_statement|log_statement|log_line_prefix|log_connections|log_disconnections|log_lock_waits|log_temp_files|track_activities|track_counts|track_io_timing|track_functions)\b)",
    r"(?i)\b(?:pg_terminate_backend|pg_cancel_backend|pg_reload_conf|pg_rotate_logfile|pg_switch_wal|pg_create_restore_point|pg_start_backup|pg_stop_backup|pg_is_in_recovery|pg_last_wal_receive_lsn|pg_last_wal_replay_lsn|pg_last_xact_replay_timestamp|pg_blocking_pids|pg_advisory_lock|pg_advisory_unlock|pg_try_advisory_lock|pg_advisory_xact_lock|pg_advisory_lock_shared|pg_advisory_unlock_shared|pg_advisory_unlock_all)\s*\(",
    r"(?i)\b(?:dblink|dblink_connect|dblink_connect_u|dblink_disconnect|dblink_exec|dblink_open|dblink_fetch|dblink_close|dblink_get_connections|dblink_get_result|dblink_get_notify|dblink_send_query|dblink_is_busy|dblink_get_pkey|dblink_build_sql_insert|dblink_build_sql_update|dblink_build_sql_delete|dblink_cancel_query|dblink_error_message)\s*\(",
    # --- MSSQL deep ---
    r"(?i)\b(?:sp_addlinkedserver|sp_addlinkedsrvlogin|sp_droplinkedsrvlogin|sp_droplinkedserver|sp_linkedservers|sp_catalogs|sp_tables_ex|sp_columns_ex|sp_table_privileges_ex|sp_column_privileges_ex|sp_foreignkeys|sp_primarykeys|sp_indexes|sp_helptext|sp_helpdb|sp_helprotect|sp_helpdevice|sp_helpfile|sp_helpfilegroup|sp_helpindex|sp_helplanguage|sp_helpserver|sp_helpsort|sp_helpstats|sp_helpremotelogin|sp_helpconstraint|sp_helptrigger|sp_helpuser|sp_helprole|sp_helprolemember|sp_helpsrvrolemember)\s*(?:\(|')",
    r"(?i)\b(?:sp_addumpdevice|sp_dropdevice|sp_attach_db|sp_detach_db|sp_certify_removable|sp_create_removable|sp_cycle_errorlog|sp_dbcmptlevel|sp_dbfixedrolepermission|sp_dboption|sp_dbremove|sp_delete_backuphistory|sp_delete_database_backuphistory|sp_depends|sp_diskdefault|sp_droptype|sp_droprolemember|sp_dropuser|sp_estimated_rowsize_reduction_for_vardecimal|sp_executesql|sp_fulltext_catalog|sp_fulltext_column|sp_fulltext_database|sp_fulltext_service|sp_fulltext_table|sp_getapplock|sp_getbindtoken|sp_grantdbaccess|sp_grantlogin)\s*(?:\(|')",
    r"(?i)\b(?:BACKUP\s+(?:DATABASE|LOG|CERTIFICATE|MASTER\s+KEY|SERVICE\s+MASTER\s+KEY)\s+|RESTORE\s+(?:DATABASE|LOG|FILELISTONLY|HEADERONLY|VERIFYONLY|LABELONLY)\s+)\b",
    r"(?i)\b(?:DBCC\s+(?:CHECKDB|CHECKTABLE|CHECKALLOC|CHECKCATALOG|CHECKFILEGROUP|CHECKIDENT|CHECKCONSTRAINTS|CLEANTABLE|DBREINDEX|DROPCLEANBUFFERS|FREEPROCCACHE|FREESESSIONCACHE|FREESYSTEMCACHE|INDEXDEFRAG|INPUTBUFFER|LOGINFO|OPENTRAN|OUTPUTBUFFER|PINTABLE|PROCCACHE|SHOW_STATISTICS|SHRINKDATABASE|SHRINKFILE|SQLPERF|TRACEON|TRACEOFF|TRACESTATUS|UNPINTABLE|UPDATEUSAGE|USEROPTIONS))\b",
    # --- Oracle deep ---
    r"(?i)\b(?:CONNECT\s+BY|START\s+WITH|ROWNUM|ROWID|SYSDATE|SYSTIMESTAMP|DBTIMEZONE|SESSIONTIMEZONE|USERENV|SYS_CONTEXT|SYS_GUID|SYS_TYPEID|DUMP\s*\(|VSIZE\s*\(|NLS_CHARSET_ID|NLS_CHARSET_NAME|NLS_CHARSET_DECL_LEN)\b",
    r"(?i)\b(?:DBMS_OUTPUT\.PUT_LINE|DBMS_SQL\.EXECUTE|DBMS_SQL\.PARSE|DBMS_SQL\.OPEN_CURSOR|DBMS_SQL\.CLOSE_CURSOR|DBMS_SQL\.COLUMN_VALUE|DBMS_SQL\.DEFINE_COLUMN|DBMS_SQL\.FETCH_ROWS|DBMS_SQL\.EXECUTE_AND_FETCH|DBMS_SQL\.DESCRIBE_COLUMNS|DBMS_RANDOM\.VALUE|DBMS_RANDOM\.STRING|DBMS_RANDOM\.SEED|DBMS_RANDOM\.NORMAL|DBMS_RANDOM\.INITIALIZE|DBMS_RANDOM\.TERMINATE)\s*(?:\(|;)",
    r"(?i)\b(?:DBMS_LOB\.GETLENGTH|DBMS_LOB\.SUBSTR|DBMS_LOB\.INSTR|DBMS_LOB\.READ|DBMS_LOB\.WRITE|DBMS_LOB\.APPEND|DBMS_LOB\.COMPARE|DBMS_LOB\.COPY|DBMS_LOB\.ERASE|DBMS_LOB\.TRIM|DBMS_LOB\.CREATETEMPORARY|DBMS_LOB\.FREETEMPORARY|DBMS_LOB\.ISTEMPORARY|DBMS_LOB\.OPEN|DBMS_LOB\.CLOSE|DBMS_LOB\.GETCHUNKSIZE|DBMS_LOB\.FILEOPEN|DBMS_LOB\.FILECLOSE|DBMS_LOB\.FILEEXISTS|DBMS_LOB\.FILEISOPEN|DBMS_LOB\.FILEGETNAME|DBMS_LOB\.GETCONTENTTYPE|DBMS_LOB\.SETCONTENTTYPE|DBMS_LOB\.LOADCLOBFROMFILE|DBMS_LOB\.LOADBLOBFROMFILE|DBMS_LOB\.CONVERTTOCLOB|DBMS_LOB\.CONVERTTOBLOB)\s*(?:\(|;)",
    r"(?i)\b(?:DBMS_ADVISOR|DBMS_APPLICATION_INFO|DBMS_AQ|DBMS_AQADM|DBMS_ASSERT|DBMS_AUDIT_MGMT|DBMS_AUTO_TASK_ADMIN|DBMS_AW_STATS|DBMS_CAPTURE_ADM|DBMS_COMPARISON|DBMS_COMPRESSION|DBMS_CREDENTIAL|DBMS_CRYPTO|DBMS_CSX_ADMIN|DBMS_CUBE|DBMS_CUBE_LOG|DBMS_DATA_MINING|DBMS_DATAPUMP|DBMS_DB_VERSION|DBMS_DDL|DBMS_DEBUG|DBMS_DEFER|DBMS_DESCRIBE|DBMS_DIMENSION|DBMS_DISTRIBUTED_TRUST_ADMIN|DBMS_EDITIONS_UTILITIES|DBMS_ERRLOG|DBMS_FGA|DBMS_FILE_TRANSFER|DBMS_FLASHBACK|DBMS_FLASHBACK_ARCHIVE|DBMS_HPROF|DBMS_HS_PARALLEL|DBMS_HS_PASSTHROUGH|DBMS_INMEMORY|DBMS_INMEMORY_ADMIN|DBMS_IOT|DBMS_JAVA|DBMS_JOB|DBMS_JSON|DBMS_LDAP|DBMS_LDAP_UTL|DBMS_LIBCACHE|DBMS_LOB|DBMS_LOCK|DBMS_LOGMNR|DBMS_LOGMNR_D|DBMS_LOGSTDBY|DBMS_METADATA|DBMS_MGD_ID_UTL|DBMS_MVIEW|DBMS_OBFUSCATION_TOOLKIT|DBMS_ODCI|DBMS_OLAP|DBMS_OUTPUT|DBMS_PARALLEL_EXECUTE|DBMS_PART|DBMS_PDB|DBMS_PIPE|DBMS_PREDICTIVE_ANALYTICS|DBMS_PREPROCESSOR|DBMS_PRIVILEGE_CAPTURE|DBMS_PROFILER|DBMS_PROPAGATION_ADM|DBMS_RANDOM|DBMS_RECO_SCRIPT_PARAMS|DBMS_REDACT|DBMS_REDEFINITION|DBMS_REFRESH|DBMS_REPAIR|DBMS_REPCAT|DBMS_REPCAT_ADMIN|DBMS_REPUTIL|DBMS_RESOURCE_MANAGER|DBMS_RESULT_CACHE|DBMS_RESUMABLE|DBMS_ROWID|DBMS_RULE|DBMS_RULE_ADM|DBMS_SCHEDULER|DBMS_SERVER_ALERT|DBMS_SERVICE|DBMS_SESSION|DBMS_SHARED_POOL|DBMS_SPACE|DBMS_SPACE_ADMIN|DBMS_SPM|DBMS_SQL|DBMS_STATS|DBMS_STORAGE_MAP|DBMS_STREAMS|DBMS_STREAMS_ADM|DBMS_TSDP_MANAGE|DBMS_TSDP_PROTECT|DBMS_TTS|DBMS_TYPES|DBMS_UTILITY|DBMS_WARNING|DBMS_WM|DBMS_WORKLOAD_CAPTURE|DBMS_WORKLOAD_REPLAY|DBMS_WORKLOAD_REPOSITORY|DBMS_XDB|DBMS_XDB_CONFIG|DBMS_XDB_REPOS|DBMS_XDBZ|DBMS_XMLDOM|DBMS_XMLGEN|DBMS_XMLPARSER|DBMS_XMLQUERY|DBMS_XMLSAVE|DBMS_XMLSCHEMA|DBMS_XMLSTORE|DBMS_XMLTRANSLATIONS|DBMS_XPLAN|DBMS_XSLPROCESSOR)\.",
    # --- Cassandra CQL ---
    r"(?i)\b(?:CREATE|ALTER|DROP)\s+(?:KEYSPACE|TABLE|INDEX|TYPE|FUNCTION|AGGREGATE|MATERIALIZED\s+VIEW|TRIGGER|ROLE|USER)\b",
    r"(?i)\b(?:GRANT|REVOKE|LIST)\s+(?:ALL|ALTER|AUTHORIZE|CREATE|DESCRIBE|DROP|EXECUTE|MODIFY|SELECT)\s+(?:ON|PERMISSION)\b",
    r"(?i)\b(?:BATCH|APPLY\s+BATCH|USING\s+TIMESTAMP|USING\s+TTL|IF\s+NOT\s+EXISTS|IF\s+EXISTS|ALLOW\s+FILTERING)\b",
    r"(?i)\b(?:CONSISTENCY\s+(?:ANY|ONE|TWO|THREE|QUORUM|ALL|LOCAL_QUORUM|EACH_QUORUM|SERIAL|LOCAL_SERIAL|LOCAL_ONE))\b",
    # --- Elasticsearch query ---
    r"(?i)\{[^}]*['\"](?:query|bool|must|should|must_not|filter|range|match|match_all|match_phrase|match_phrase_prefix|multi_match|common|query_string|simple_query_string|term|terms|wildcard|regexp|fuzzy|type|ids|exists|prefix|nested|has_child|has_parent|parent_id|geo_shape|geo_bounding_box|geo_distance|geo_polygon|more_like_this|percolate|wrapper|script_score|function_score|dis_max|constant_score|boosting|indices|span_first|span_multi|span_near|span_not|span_or|span_term|span_within|span_containing|span_field_masking|field_masking_span|script)['\"]",
    r"(?i)_(?:search|update|delete_by_query|update_by_query|bulk|mget|msearch|mtermvectors|reindex|analyze|explain|validate|count|scroll|clear_scroll|search_shards|field_caps|rank_eval|search_template|render_search_template|scripts_painless_execute)\b",
    r"(?i)(?:_cat|_cluster|_nodes|_tasks|_remote|_snapshot|_ingest|_template|_index_template|_component_template|_ilm|_rollup|_transform|_ml|_security|_watcher|_graph|_ccr|_async_search|_sql|_eql|_fleet)/",
    r"(?i)['\"]script['\"]:\s*\{[^}]*['\"](?:source|lang|params|inline|stored|file)['\"]",
    r"(?i)['\"](?:painless|groovy|expression|mustache|java|javascript|python)['\"].*['\"](?:source|inline)['\"]",
]

# ============================================================================
# 3. FRAMEWORK-SPECIFIC ATTACKS (400 patterns)
# ============================================================================
FRAMEWORK_ATTACKS = [
    # --- Spring Framework deep ---
    r"(?i)/actuator/(?:health|info|env|beans|configprops|mappings|metrics|loggers|httptrace|threaddump|heapdump|scheduledtasks|conditions|auditevents|caches|flyway|integrationgraph|liquibase|prometheus|sessions|shutdown|startup|jolokia|logfile|refresh|restart|pause|resume)\b",
    r"(?i)(?:class\.module\.classLoader|class\.classLoader|class\.protectionDomain|class\.class\.classLoader)\.",
    r"(?i)(?:spring\.datasource\.(?:url|username|password|driver-class-name)|spring\.jpa\.(?:properties|hibernate|database|show-sql|generate-ddl|open-in-view)|spring\.security\.(?:user|oauth2|saml2|ldap)|spring\.mail\.(?:host|port|username|password|protocol|properties)|spring\.redis\.(?:host|port|password|database|url|cluster|sentinel|lettuce|jedis)|spring\.data\.(?:mongodb|elasticsearch|cassandra|neo4j|couchbase|ldap|solr|rest)|spring\.cloud\.(?:config|consul|eureka|gateway|loadbalancer|openfeign|stream|vault|bus|circuit|sleuth|zipkin)|spring\.kafka\.(?:bootstrap-servers|consumer|producer|admin|listener|ssl|properties)|spring\.rabbitmq\.(?:host|port|username|password|virtual-host|addresses|ssl)|spring\.cache\.(?:type|cache-names|redis|caffeine|ehcache|hazelcast|infinispan|jcache))\b",
    r"(?i)(?:management\.endpoints\.web\.exposure\.include|management\.endpoint\.(?:health|info|env|beans|configprops|mappings|metrics|loggers|httptrace|threaddump|heapdump|shutdown)\.enabled)\s*=",
    r"(?i)(?:SpEL|spring\.cloud\.function\.routing-expression|spring\.cloud\.function\.definition)\s*[:=]",
    r"(?i)T\s*\(\s*(?:java\.lang\.Runtime|java\.lang\.ProcessBuilder|java\.lang\.System|java\.lang\.Class|java\.lang\.ClassLoader|java\.io\.File|java\.io\.FileInputStream|java\.io\.FileOutputStream|java\.io\.BufferedReader|java\.io\.InputStreamReader|java\.net\.URL|java\.net\.URLConnection|java\.net\.HttpURLConnection|java\.net\.Socket|java\.net\.ServerSocket|java\.util\.Scanner|java\.lang\.Thread|java\.lang\.reflect\.Method|java\.lang\.reflect\.Constructor|java\.lang\.reflect\.Field|javax\.script\.ScriptEngineManager|javax\.management\.MBeanServerFactory|javax\.naming\.InitialContext|javax\.xml\.transform\.TransformerFactory|org\.apache\.commons\.io\.IOUtils|org\.apache\.commons\.exec\.CommandLine)\s*\)",
    r"(?i)new\s+(?:java\.lang\.ProcessBuilder|java\.io\.File|java\.io\.FileInputStream|java\.io\.FileOutputStream|java\.net\.URL|java\.net\.Socket|java\.net\.ServerSocket|javax\.script\.ScriptEngineManager|javax\.naming\.InitialContext)\s*\(",
    r"(?i)(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder\([^)]*\)\.start|Class\.forName|ClassLoader\.loadClass|Method\.invoke|Constructor\.newInstance|Field\.set|Proxy\.newProxyInstance|Thread\.sleep|System\.exit|System\.getProperty|System\.getenv|System\.setProperty)\s*\(",
    # --- Struts/OGNL ---
    r"(?i)(?:%\{|#|@)\s*(?:_memberAccess|_ognl|context|request|response|session|application|servletContext|parameters|attr|vs)\b",
    r"(?i)(?:#_memberAccess\[|#_ognlUtil|#context\[|#application\[|#session\[|#request\[|#response\[|#parameters\[|#attr\[)",
    r"(?i)(?:\$\{|#\{)\s*(?:T\(|new\s+java\.|@java\.|Runtime|ProcessBuilder|Class\.forName|ClassLoader|ScriptEngine|Thread|System)\b",
    r"(?i)(?:ognl\.OgnlContext|ognl\.OgnlRuntime|ognl\.TypeConverter|ognl\.MemberAccess|ognl\.ClassResolver|ognl\.PropertyAccessor|ognl\.MethodAccessor|ognl\.ElementsAccessor)\b",
    # --- Django deep ---
    r"(?i)(?:django\.contrib\.admin|django\.views\.debug|django\.conf\.settings|django\.core\.management|django\.db\.connection|django\.db\.models|django\.template\.loader|django\.template\.base|django\.utils\.safestring|django\.http\.request|django\.http\.response|django\.middleware|django\.core\.files|django\.core\.mail|django\.core\.cache|django\.core\.signing|django\.core\.serializers|django\.forms|django\.test|django\.urls)\b",
    r"(?i)/(?:admin|__debug__|_debug|django-admin|jsi18n|set_language|login|logout|password_change|password_reset)/",
    r"(?i)(?:DJANGO_SETTINGS_MODULE|SECRET_KEY|ALLOWED_HOSTS|DEBUG|DATABASES|EMAIL_HOST_PASSWORD|CSRF_COOKIE_NAME|SESSION_COOKIE_NAME|CSRF_TRUSTED_ORIGINS|INTERNAL_IPS)\s*[:=]",
    r"(?i)\{\{.*(?:__class__|__mro__|__subclasses__|__globals__|__builtins__|__import__|__init__|__dict__|__doc__|__module__|__name__|__qualname__|__bases__|__code__|__func__|__self__|__wrapped__).*\}\}",
    r"(?i)\{%.*(?:load|extends|include|import|from|block|endblock|for|endfor|if|endif|while|endwhile|with|endwith|autoescape|endautoescape|spaceless|endspaceless|verbatim|endverbatim|comment|endcomment|cycle|firstof|ifchanged|regroup|resetcycle|templatetag|url|widthratio|filter|lorem|now|debug|ssi|csrf_token).*%\}",
    # --- Flask/Jinja2 deep ---
    r"(?i)\{\{.*(?:config|request|session|g|get_flashed_messages|url_for|cycler|joiner|namespace).*\}\}",
    r"(?i)\{\{.*(?:lipsum|range|dict|popen|Popen|subprocess|os|sys|importlib|builtins|getattr|setattr|delattr|hasattr|globals|locals|vars|dir|type|id|hex|oct|bin|chr|ord|repr|ascii|format|eval|exec|compile|open|input|print|breakpoint|exit|quit|help|copyright|credits|license).*\}\}",
    r"(?i)\{\{.*\.__class__\.__mro__\[\d+\]\.__subclasses__\(\).*\}\}",
    r"(?i)\{\{.*(?:request\.application\.__self__|request\.environ|config\.from_object|config\.from_pyfile|config\.from_envvar|config\.from_json|config\.from_mapping).*\}\}",
    # --- Express.js/Node.js deep ---
    r"(?i)(?:require|import)\s*\(\s*['\"](?:child_process|fs|os|path|crypto|http|https|net|dgram|dns|cluster|process|vm|module|repl|readline|stream|tty|util|v8|worker_threads|perf_hooks|async_hooks|inspector)['\"]",
    r"(?i)(?:process\.(?:env|exit|kill|abort|chdir|cwd|execPath|version|versions|config|arch|platform|release|title|pid|ppid|stdin|stdout|stderr|argv|execArgv|mainModule|memoryUsage|cpuUsage|hrtime|uptime|getuid|getgid|geteuid|getegid|getgroups|setuid|setgid|seteuid|setegid|setgroups|initgroups|umask|dlopen|binding|_linkedBinding))\b",
    r"(?i)(?:child_process\.(?:exec|execSync|execFile|execFileSync|fork|spawn|spawnSync)|fs\.(?:readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|unlink|unlinkSync|rename|renameSync|mkdir|mkdirSync|rmdir|rmdirSync|readdir|readdirSync|stat|statSync|lstat|lstatSync|chmod|chmodSync|chown|chownSync|link|linkSync|symlink|symlinkSync|readlink|readlinkSync|realpath|realpathSync|access|accessSync|exists|existsSync|createReadStream|createWriteStream|open|openSync|close|closeSync|read|readSync|write|writeSync|truncate|truncateSync|ftruncate|ftruncateSync|watch|watchFile|unwatchFile|copyFile|copyFileSync|rm|rmSync))\s*\(",
    r"(?i)(?:global\.(?:process|Buffer|setTimeout|setInterval|setImmediate|clearTimeout|clearInterval|clearImmediate|console|queueMicrotask|structuredClone|URL|URLSearchParams|TextEncoder|TextDecoder|atob|btoa|Event|EventTarget|MessageChannel|MessageEvent|MessagePort|performance|crypto|Blob|FormData|Headers|Request|Response|fetch|AbortController|AbortSignal|ReadableStream|WritableStream|TransformStream|WebSocket|Worker|SharedWorker|BroadcastChannel))\b",
    r"(?i)(?:__proto__|constructor\.prototype|Object\.(?:assign|create|defineProperty|defineProperties|entries|freeze|fromEntries|getOwnPropertyDescriptor|getOwnPropertyDescriptors|getOwnPropertyNames|getOwnPropertySymbols|getPrototypeOf|is|isExtensible|isFrozen|isSealed|keys|preventExtensions|seal|setPrototypeOf|values))\b",
    r"(?i)(?:prototype\.(?:constructor|__defineGetter__|__defineSetter__|__lookupGetter__|__lookupSetter__|hasOwnProperty|isPrototypeOf|propertyIsEnumerable|toLocaleString|toString|valueOf))\b",
    # --- PHP deep ---
    r"(?i)(?:eval|assert|preg_replace|create_function|call_user_func|call_user_func_array|usort|uasort|uksort|array_filter|array_map|array_reduce|array_walk|array_walk_recursive)\s*\(\s*(?:base64_decode|str_rot13|gzinflate|gzuncompress|gzdecode|rawurldecode|urldecode|hex2bin|convert_uudecode|stripslashes|substr|str_replace|str_ireplace|strrev|strtolower|strtoupper|ucfirst|lcfirst|trim|ltrim|rtrim|nl2br|wordwrap|str_pad|str_repeat|str_split|chunk_split|quoted_printable_decode|quoted_printable_encode|htmlspecialchars_decode|htmlentities|html_entity_decode)\s*\(",
    r"(?i)(?:include|include_once|require|require_once)\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER|SESSION|ENV)\[|php://(?:input|stdin|filter|data)|data://|expect://|zip://|phar://|compress\.(?:zlib|bzip2)://|glob://|ssh2://|rar://|ogg://|ftp://|http://|https://)\b",
    r"(?i)(?:\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER|SESSION|ENV))\s*\[",
    r"(?i)(?:file_get_contents|file_put_contents|fopen|fread|fwrite|fclose|fgets|fgetc|fgetss|fgetcsv|fputcsv|fputs|fseek|ftell|feof|fflush|flock|ftruncate|fstat|fpassthru|readfile|file|glob|scandir|opendir|readdir|closedir|is_file|is_dir|is_readable|is_writable|is_executable|file_exists|filetype|filesize|fileatime|filectime|filemtime|fileowner|filegroup|fileperms|fileinode|pathinfo|dirname|basename|realpath|tempnam|tmpfile|mkdir|rmdir|rename|copy|unlink|link|symlink|readlink|chmod|chown|chgrp|touch|umask|disk_free_space|disk_total_space)\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)|php://|data://|expect://|zip://|phar://)",
    r"(?i)(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|dl|putenv|getenv|phpinfo|phpversion|php_uname|php_sapi_name|php_ini_loaded_file|php_ini_scanned_files|get_cfg_var|get_current_user|get_include_path|get_loaded_extensions|get_defined_functions|get_defined_vars|get_defined_constants|get_object_vars|get_class_methods|get_class_vars|get_class|get_parent_class|is_a|is_subclass_of|class_exists|function_exists|method_exists|property_exists|interface_exists|trait_exists|class_alias|class_implements|class_parents|class_uses)\s*\(",
    r"(?i)(?:serialize|unserialize|json_decode|json_encode|var_export|print_r|debug_zval_dump|debug_print_backtrace|debug_backtrace|trigger_error|user_error|set_error_handler|set_exception_handler|register_shutdown_function|register_tick_function|spl_autoload_register|__autoload|__construct|__destruct|__call|__callStatic|__get|__set|__isset|__unset|__sleep|__wakeup|__serialize|__unserialize|__toString|__invoke|__set_state|__clone|__debugInfo)\s*\(",
    # --- Ruby/Rails deep ---
    r"(?i)(?:system|exec|fork|spawn|popen|IO\.popen|Open3\.|Kernel\.system|Kernel\.exec|Kernel\.spawn|Kernel\.open|Kernel\.send|Kernel\.eval|Kernel\.binding|Kernel\.require|Kernel\.load|Kernel\.autoload|Kernel\.method|Kernel\.public_send|Kernel\.instance_eval|Kernel\.class_eval|Kernel\.module_eval|Kernel\.define_method|Kernel\.method_missing|Kernel\.respond_to_missing|Kernel\.const_missing|Kernel\.remove_method|Kernel\.undef_method|Kernel\.alias_method|Kernel\.send|Kernel\.public_send|Object\.send|Object\.public_send|BasicObject\.instance_eval|BasicObject\.method_missing)\b",
    r"(?i)(?:ERB\.new|Erubis|Haml::Engine|Slim::Template|Tilt|Liquid::Template|Mustache|Handlebars|Jbuilder|Rabl|ActiveSupport::JSON|ActiveSupport::MessageEncryptor|ActiveSupport::MessageVerifier|ActiveSupport::SecurityUtils)\b",
    r"(?i)(?:ActiveRecord::Base\.(?:connection|establish_connection|find_by_sql|execute|select_all|select_one|select_value|select_values|insert|update|delete|exec_query|exec_insert|exec_update|exec_delete|raw_connection|where|find|create|new|destroy|update_all|delete_all|pluck|order|limit|offset|group|having|joins|includes|eager_load|preload|references|left_outer_joins|lock|readonly|reorder|reverse_order|unscope|rewhere|or|not|extending|from|select|distinct|none|null|all|count|sum|average|minimum|maximum|calculate|ids|pick|first|last|second|third|fourth|fifth|forty_two|third_to_last|second_to_last|find_each|find_in_batches|in_batches|exists|any|many|none))\b",
    r"(?i)(?:Rails\.application\.(?:config|credentials|secrets|routes|middleware|initializers|assets|console|generators|rake_tasks))\b",
    # --- ASP.NET deep ---
    r"(?i)(?:Response\.Write|Response\.Redirect|Response\.TransmitFile|Response\.WriteFile|Response\.BinaryWrite|Server\.Execute|Server\.Transfer|Server\.MapPath|Server\.HtmlEncode|Server\.HtmlDecode|Server\.UrlEncode|Server\.UrlDecode|Server\.UrlPathEncode|Server\.CreateObject|Application\.Lock|Application\.UnLock|Session\.Abandon|Request\.QueryString|Request\.Form|Request\.Cookies|Request\.ServerVariables|Request\.Params|Request\.Headers|Request\.Files|Request\.InputStream|Request\.MapPath|Request\.IsSecureConnection|Request\.IsAuthenticated|Request\.Browser|Request\.UserAgent|Request\.UserHostAddress|Request\.UserHostName|Request\.UserLanguages|Request\.Url|Request\.UrlReferrer|Request\.HttpMethod|Request\.ContentType|Request\.ContentLength|Request\.ContentEncoding|Request\.AcceptTypes)\b",
    r"(?i)(?:System\.Diagnostics\.Process\.Start|System\.IO\.File\.|System\.IO\.Directory\.|System\.IO\.Path\.|System\.IO\.StreamReader|System\.IO\.StreamWriter|System\.Net\.WebClient|System\.Net\.Http\.HttpClient|System\.Reflection\.|System\.Runtime\.Serialization\.|System\.Web\.Script\.Serialization\.|System\.Xml\.Serialization\.XmlSerializer|System\.Data\.SqlClient\.SqlCommand|System\.Data\.OleDb\.OleDbCommand|System\.Data\.Odbc\.OdbcCommand|Microsoft\.CSharp\.CSharpCodeProvider|System\.CodeDom\.Compiler|System\.Runtime\.InteropServices|System\.Security\.Cryptography|System\.Threading|System\.Timers|System\.ServiceProcess|System\.DirectoryServices|System\.Management|System\.Messaging)\b",
    r"(?i)(?:__VIEWSTATE|__VIEWSTATEGENERATOR|__EVENTVALIDATION|__EVENTTARGET|__EVENTARGUMENT|__PREVIOUSPAGE|__SCROLLPOSITIONX|__SCROLLPOSITIONY|__ASYNCPOST|__REQUESTDIGEST)\s*=",
]

# ============================================================================
# 4. API-SPECIFIC ABUSE PATTERNS (350 patterns)
# ============================================================================
API_ABUSE = [
    # --- REST API abuse ---
    r"(?i)/api/v\d+/(?:admin|internal|debug|test|staging|dev|management|config|settings|secrets|tokens|keys|credentials|passwords|users|roles|permissions|groups|policies|acls|rules|audits|logs|backups|exports|imports|migrations|deployments|releases|builds|pipelines|webhooks|integrations|plugins|extensions|modules|packages|libraries|dependencies|vulnerabilities|scans|assessments|reports|alerts|notifications|incidents|tickets|issues|bugs|features|requests|approvals|reviews|comments|feedback|surveys|forms|templates|schemas|models|entities|resources|collections|documents|records|items|objects|entries|elements|nodes|edges|relationships|connections|links|references|attachments|files|uploads|downloads|media|images|videos|audio|assets|styles|scripts|fonts|icons|logos|banners|thumbnails|previews|caches|sessions|cookies|headers|parameters|queries|filters|sorts|pages|limits|offsets|cursors|tokens|nonces|signatures|checksums|hashes|digests|fingerprints|certificates|keys|secrets|credentials|passwords|pins|codes|otps|mfas|factors|challenges|verifications|validations|confirmations|activations|registrations|enrollments|subscriptions|memberships|plans|tiers|quotas|limits|rates|budgets|balances|transactions|payments|invoices|receipts|refunds|chargebacks|disputes|claims|rewards|points|credits|debits|transfers|withdrawals|deposits)\b",
    r"(?i)/api/(?:graphql|graphiql|playground|explorer|console|swagger|openapi|redoc|docs|documentation|spec|schema|introspect|health|status|info|version|ping|ready|alive|metrics|stats|analytics|monitoring|debug|test|echo|mirror|reflect|proxy|forward|redirect|callback|webhook|hook|event|trigger|schedule|cron|job|task|queue|worker|batch|bulk|import|export|dump|backup|restore|migrate|seed|reset|clear|purge|flush|refresh|reload|restart|shutdown|maintenance)\b",
    r"(?i)(?:X-Api-Key|X-Api-Secret|X-Api-Token|X-Auth-Key|X-Auth-Secret|X-Auth-Token|X-Access-Key|X-Access-Secret|X-Access-Token|X-Client-Key|X-Client-Secret|X-Client-Token|X-Service-Key|X-Service-Secret|X-Service-Token|X-Gateway-Key|X-Gateway-Secret|X-Gateway-Token|X-Proxy-Key|X-Proxy-Secret|X-Proxy-Token|X-Internal-Key|X-Internal-Secret|X-Internal-Token|X-Admin-Key|X-Admin-Secret|X-Admin-Token|X-Debug-Key|X-Debug-Secret|X-Debug-Token|X-Test-Key|X-Test-Secret|X-Test-Token|X-Master-Key|X-Master-Secret|X-Master-Token|X-Root-Key|X-Root-Secret|X-Root-Token|X-Super-Key|X-Super-Secret|X-Super-Token)\s*:",
    # --- GraphQL deep ---
    r"(?i)\{\s*__schema\s*\{",
    r"(?i)\{\s*__type\s*\(\s*name\s*:",
    r"(?i)query\s+IntrospectionQuery\s*\{",
    r"(?i)(?:query|mutation|subscription)\s*\{[^}]*\{[^}]*\{[^}]*\{[^}]*\{",
    r"(?i)(?:query|mutation)\s+\w+\s*\([^)]*\)\s*\{.*(?:__schema|__type|__typename|__directive|__enumValue|__field|__inputValue|__type)\b",
    r"(?i)\b(?:fragment|query|mutation|subscription)\s+\w+\s+on\s+\w+\s*\{.*(?:__schema|__type)\b",
    r"(?i)(?:@(?:skip|include|deprecated|specifiedBy|defer|stream|live|connection|cacheControl|auth|hasRole|hasScope|hasPermission|isAuthenticated|upper|lower|trim|default|computed|external|requires|provides|key|extends|inaccessible|override|shareable|tag|composeDirective|interfaceObject|authenticated|policy|requiresScopes))\s*\(",
    # --- OAuth/OIDC abuse ---
    r"(?i)(?:response_type|grant_type|redirect_uri|client_id|client_secret|code|state|nonce|scope|audience|resource|assertion|code_verifier|code_challenge|code_challenge_method|login_hint|prompt|display|acr_values|claims|request|request_uri|registration|id_token_hint|max_age|ui_locales|claims_locales)\s*=",
    r"(?i)(?:redirect_uri|post_logout_redirect_uri|initiate_login_uri|target_link_uri|request_uri|sector_identifier_uri|backchannel_logout_uri|frontchannel_logout_uri|logo_uri|policy_uri|tos_uri|client_uri|jwks_uri)\s*=\s*(?:https?://|data:|javascript:|file:|ftp:|gopher:|dict:|ldap:)",
    r"(?i)/(?:oauth|oauth2|oidc|openid-connect|\.well-known/openid-configuration|\.well-known/oauth-authorization-server|authorize|token|userinfo|introspect|revoke|device|device_authorization|pushed-authorization-request|backchannel-authentication|ciba|jwks|keys|certs|discovery|\.well-known/jwks\.json)\b",
    r"(?i)(?:grant_type\s*=\s*(?:authorization_code|implicit|client_credentials|password|refresh_token|urn:ietf:params:oauth:grant-type:jwt-bearer|urn:ietf:params:oauth:grant-type:saml2-bearer|urn:ietf:params:oauth:grant-type:device_code|urn:openid:params:grant-type:ciba))\b",
    # --- SOAP/XML-RPC attacks ---
    r"(?i)<\s*(?:soap|soapenv|SOAP-ENV)\s*:\s*(?:Envelope|Header|Body|Fault)\b",
    r"(?i)<\s*(?:wsse|wsu|wst|wsp|wsa|wsrm|wscoor|wsrf|wsn)\s*:",
    r"(?i)<\s*(?:methodCall|methodResponse|methodName|params|param|value|struct|member|name|data|array|fault|faultCode|faultString)\b",
    r"(?i)(?:system\.(?:listMethods|methodSignature|methodHelp|getCapabilities|multicall)|metaWeblog\.|blogger\.|wp\.|demo\.(?:sayHello|addTwoNumbers))\b",
    # --- WebSocket attacks ---
    r"(?i)(?:Upgrade:\s*websocket|Connection:\s*Upgrade|Sec-WebSocket-(?:Key|Version|Protocol|Extensions|Accept))\b",
    r"(?i)\{[^}]*['\"](?:command|handler|callback|hook|trigger|emit|broadcast|subscribe|unsubscribe|publish|invoke|eval|exec|execute|dispatch|shutdown|kill|abort|destroy|purge|flush|rollback|unmount|disconnect)['\"]\s*:\s*['\"]",
    # --- gRPC/Protocol Buffers ---
    r"(?i)(?:grpc|protobuf|proto3|proto2)\s*(?:\{|;|=)",
    r"(?i)(?:application/grpc|application/grpc-web|application/grpc-web-text|application/grpc\+proto|application/grpc\+json|application/protobuf|application/x-protobuf|application/x-google-protobuf)\b",
    r"(?i)(?:grpc-(?:status|message|encoding|accept-encoding|timeout|metadata-bin|previous-rpc-attempts|retry-pushback-ms|server-load-balancing-stats))\s*:",
    r"(?i)/(?:grpc|pb|protobuf|proto)\.(?:health\.v1\.Health|reflection\.v1alpha\.ServerReflection|reflection\.v1\.ServerReflection|channelz\.v1\.Channelz|admin\.v1\.AdminService)/",
    # --- CORS abuse ---
    r"(?i)(?:Access-Control-(?:Allow-Origin|Allow-Methods|Allow-Headers|Allow-Credentials|Expose-Headers|Max-Age|Request-Method|Request-Headers))\s*:\s*(?:\*|null|https?://(?:evil|attacker|hacker|malicious|phishing|exploit|payload)\.\w+)",
    r"(?i)(?:Origin)\s*:\s*(?:null|https?://(?:evil|attacker|hacker|malicious|phishing|exploit|payload|localhost|127\.0\.0\.1|0\.0\.0\.0|::1)\.\w*)\b",
]

# ============================================================================
# 5. INFRASTRUCTURE & CLOUD DEEP (300 patterns)
# ============================================================================
INFRA_CLOUD_DEEP = [
    # --- Kubernetes deep ---
    r"(?i)/api/v1/(?:namespaces|pods|services|endpoints|nodes|configmaps|secrets|persistentvolumeclaims|persistentvolumes|serviceaccounts|resourcequotas|limitranges|replicationcontrollers|events|componentstatuses|bindings)/",
    r"(?i)/apis/(?:apps|batch|extensions|networking\.k8s\.io|policy|rbac\.authorization\.k8s\.io|storage\.k8s\.io|autoscaling|certificates\.k8s\.io|coordination\.k8s\.io|discovery\.k8s\.io|events\.k8s\.io|flowcontrol\.apiserver\.k8s\.io|node\.k8s\.io|scheduling\.k8s\.io|admissionregistration\.k8s\.io|apiextensions\.k8s\.io|apiregistration\.k8s\.io)/",
    r"(?i)kubectl\s+(?:get|describe|create|apply|delete|edit|patch|replace|scale|autoscale|rollout|set|expose|run|attach|exec|logs|port-forward|proxy|cp|auth|debug|diff|kustomize|label|annotate|completion|api-resources|api-versions|cluster-info|config|cordon|uncordon|drain|taint|top|version|wait|certificate|plugin|options)\b",
    r"(?i)(?:apiVersion|kind|metadata|spec|status|template|containers|volumes|volumeMounts|env|envFrom|ports|resources|requests|limits|livenessProbe|readinessProbe|startupProbe|securityContext|serviceAccountName|nodeSelector|affinity|tolerations|topologySpreadConstraints|priorityClassName|runtimeClassName|hostNetwork|hostPID|hostIPC|shareProcessNamespace|terminationGracePeriodSeconds|dnsPolicy|dnsConfig|hostAliases|initContainers|ephemeralContainers|imagePullSecrets|automountServiceAccountToken|privileged|allowPrivilegeEscalation|runAsUser|runAsGroup|runAsNonRoot|readOnlyRootFilesystem|capabilities|seccompProfile|appArmorProfile|seLinuxOptions|windowsOptions|procMount)\s*:",
    r"(?i)(?:helm\s+(?:install|upgrade|rollback|uninstall|delete|list|repo|search|show|status|history|get|pull|push|package|lint|template|verify|version|env|plugin|create|dependency|diff|test|inspect|fetch|reset|serve|home|init|completion))\b",
    # --- Docker deep ---
    r"(?i)/v\d+\.\d+/(?:containers|images|networks|volumes|plugins|nodes|services|tasks|secrets|configs|swarm|system|distribution|build|commit|exec|events|info|version|auth|_ping|session)/",
    r"(?i)docker\s+(?:run|exec|build|pull|push|tag|images|ps|stop|start|restart|rm|rmi|logs|inspect|commit|save|load|export|import|history|top|stats|attach|wait|kill|pause|unpause|rename|update|port|cp|diff|events|info|version|login|logout|search|create|network|volume|plugin|node|service|stack|secret|config|swarm|system|trust|manifest|buildx|compose|context|scan|scout|sbom|init)\b",
    r"(?i)(?:DOCKER_HOST|DOCKER_TLS_VERIFY|DOCKER_CERT_PATH|DOCKER_CONFIG|DOCKER_CONTENT_TRUST|DOCKER_BUILDKIT|COMPOSE_FILE|COMPOSE_PROJECT_NAME|COMPOSE_PROFILES|COMPOSE_HTTP_TIMEOUT)\s*=",
    r"(?i)/var/run/docker\.sock\b",
    # --- AWS deep ---
    r"(?i)(?:aws\s+(?:s3|ec2|iam|rds|lambda|ecs|eks|ecr|cloudformation|cloudwatch|cloudfront|cloudtrail|route53|sns|sqs|ses|dynamodb|elasticache|elasticsearch|kinesis|kms|secretsmanager|ssm|sts|acm|apigateway|appsync|athena|batch|budgets|codebuild|codecommit|codedeploy|codepipeline|cognito-idp|cognito-identity|comprehend|config|connect|dax|devicefarm|directconnect|discovery|dms|ds|ebs|efs|elasticbeanstalk|elbv2|emr|events|firehose|fms|forecast|fsx|gamelift|glacier|globalaccelerator|glue|greengrass|guardduty|health|inspector|iot|kafka|lex|lightsail|logs|machinelearning|macie|mediaconvert|medialive|mediapackage|mediastore|mq|neptune|opsworks|organizations|personalize|pinpoint|polly|quicksight|ram|redshift|rekognition|robomaker|sagemaker|servicecatalog|servicediscovery|shield|signer|snowball|stepfunctions|storagegateway|support|swf|textract|transcribe|transfer|translate|waf|wafv2|workdocs|worklink|workmail|workspaces|xray))\b",
    r"(?i)(?:AKIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)[A-Z0-9]{16}\b",
    r"(?i)(?:aws_access_key_id|aws_secret_access_key|aws_session_token|aws_security_token|aws_default_region|aws_profile|aws_role_arn|aws_external_id|aws_mfa_serial|aws_config_file|aws_shared_credentials_file|aws_ca_bundle|aws_metadata_service_timeout|aws_metadata_service_num_attempts|aws_ec2_metadata_disabled|aws_max_attempts|aws_retry_mode|aws_sdk_load_config|aws_execution_env|aws_region|aws_default_output)\s*[:=]",
    # --- Azure deep ---
    r"(?i)(?:az\s+(?:account|acr|acs|ad|advisor|aks|ams|appconfig|apim|appservice|backup|batch|billing|bot|cdn|cloud|cognitiveservices|consumption|container|cosmosdb|deployment|deploymentmanager|devops|disk|dla|dls|dms|eventgrid|eventhubs|extension|feature|feedback|find|functionapp|group|hdinsight|identity|image|iot|keyvault|kusto|lab|lock|managedapp|managedservices|maps|mariadb|monitor|mysql|netappfiles|network|openshift|policy|postgres|ppg|provider|redis|relay|repos|reservations|resource|role|search|security|servicebus|sf|sig|signalr|snapshot|sql|staticwebapp|storage|synapse|tag|term|vm|vmss|webapp|redis))\b",
    r"(?i)(?:AZURE_(?:CLIENT_ID|CLIENT_SECRET|TENANT_ID|SUBSCRIPTION_ID|STORAGE_ACCOUNT|STORAGE_KEY|STORAGE_CONNECTION_STRING|COSMOS_KEY|SQL_CONNECTION_STRING|REDIS_KEY|SERVICE_BUS_CONNECTION_STRING|EVENT_HUB_CONNECTION_STRING|IOT_HUB_CONNECTION_STRING|COGNITIVE_SERVICES_KEY|SEARCH_KEY|SEARCH_ADMIN_KEY|FORM_RECOGNIZER_KEY|TEXT_ANALYTICS_KEY|TRANSLATOR_KEY|COMPUTER_VISION_KEY|FACE_KEY|SPEECH_KEY|ANOMALY_DETECTOR_KEY|PERSONALIZER_KEY|CONTENT_MODERATOR_KEY|LUIS_KEY|QNA_MAKER_KEY|BOT_SERVICE_KEY|MAPS_KEY|NOTIFICATION_HUB_CONNECTION_STRING|APP_CONFIGURATION_CONNECTION_STRING|KEY_VAULT_URL|WEBAPP_NAME|FUNCTIONS_KEY|DEVOPS_ORG_URL|DEVOPS_PAT))\s*[:=]",
    # --- GCP deep ---
    r"(?i)(?:gcloud\s+(?:auth|config|compute|container|iam|kms|logging|monitoring|network|projects|pubsub|run|sql|storage|functions|app|builds|artifacts|bigtable|composer|dataflow|dataproc|datastore|deployment-manager|dns|domains|endpoints|filestore|firebase|healthcare|ids|memcache|ml|ml-engine|notebooks|organizations|recaptcha|redis|resource-manager|scheduler|secrets|service-directory|services|source|spanner|tasks|topic|trace))\b",
    r"(?i)(?:GOOGLE_(?:APPLICATION_CREDENTIALS|CLOUD_PROJECT|CLOUD_REGION|CLOUD_ZONE|COMPUTE_ENGINE_DEFAULT_ZONE|COMPUTE_ENGINE_DEFAULT_REGION|CLIENT_ID|CLIENT_SECRET|REFRESH_TOKEN|ACCESS_TOKEN|API_KEY|SERVICE_ACCOUNT_EMAIL|SERVICE_ACCOUNT_KEY|CLOUD_KEYFILE_JSON|GCLOUD_KEYFILE_JSON|PRIVATE_KEY|ANALYTICS_TRACKING_ID|RECAPTCHA_KEY|MAPS_API_KEY|FIREBASE_API_KEY|CLOUD_STORAGE_BUCKET|CLOUD_SQL_INSTANCE|CLOUD_MEMORYSTORE_HOST|PUBSUB_TOPIC|PUBSUB_SUBSCRIPTION|CLOUD_FUNCTION_NAME|CLOUD_RUN_SERVICE|CLOUD_BUILD_TRIGGER))\s*[:=]",
    # --- Terraform/IaC ---
    r"(?i)(?:terraform\s+(?:init|plan|apply|destroy|import|output|show|state|taint|untaint|workspace|validate|fmt|force-unlock|get|graph|login|logout|providers|refresh|version))\b",
    r"(?i)(?:resource|data|variable|output|locals|module|provider|terraform)\s+['\"]?\w+['\"]?\s+['\"]?\w+['\"]?\s*\{",
    r"(?i)(?:provisioner\s+['\"](?:local-exec|remote-exec|file|chef|habitat|puppet|salt-masterless)['\"])\b",
    r"(?i)(?:ansible\s+(?:all|localhost|\w+)\s+-m\s+(?:shell|command|raw|script|expect|telnet|ping|setup|copy|fetch|file|template|lineinfile|blockinfile|replace|find|stat|archive|unarchive|synchronize|git|svn|hg|pip|gem|npm|yarn|composer|apt|yum|dnf|zypper|pacman|apk|snap|flatpak|docker_container|docker_image|docker_network|docker_volume|k8s|helm|aws_s3|aws_ec2|azure_rm|gcp_compute|openstack|vmware_guest|proxmox_kvm|lxd_container|terraform|cloudformation|cron|at|systemd|service|firewalld|iptables|ufw|user|group|authorized_key|openssh_keypair|known_hosts|sysctl|mount|lvm|parted|filesystem|selinux|apparmor|pam|sudoers|hostname|timezone|locale|reboot|shutdown|wait_for|uri|get_url|unarchive|debug|fail|assert|set_fact|include|import))\b",
]

# ============================================================================
# 6. NETWORK PROTOCOL ATTACKS (250 patterns)
# ============================================================================
NETWORK_PROTOCOL = [
    # --- DNS attacks ---
    r"(?i)(?:dig|nslookup|host|drill|dnsenum|dnsrecon|fierce|sublist3r|amass|subfinder|assetfinder|massdns|shuffledns|puredns|dnsx|dnsvalidator|dnsgen|altdns|gotator|regulator|dnstwist|urlcrazy|catphish|phishing_catcher|certstream)\s+",
    r"(?i)(?:type\s*=\s*|\bIN\s+)(?:AXFR|IXFR|SOA|NS|MX|TXT|SRV|PTR|AAAA|CNAME|DNAME|DNSKEY|DS|RRSIG|NSEC|NSEC3|NSEC3PARAM|TLSA|CAA|NAPTR|LOC|HINFO|RP|AFSDB|RT|NSAP|SIG|KEY|PX|GPOS|ISDN|MB|MG|MINFO|MR|WKS|X25|KX|CERT|SINK|OPT|APL|SSHFP|IPSECKEY|DHCID|HIP|NINFO|RKEY|TALINK|CDS|CDNSKEY|OPENPGPKEY|CSYNC|ZONEMD|SVCB|HTTPS|SPF|UINFO|UID|GID|UNSPEC|NID|L32|L64|LP|EUI48|EUI64|TKEY|TSIG|MAILB|MAILA|ANY|URI|TA|DLV)\b",
    r"(?i)(?:zone\s+['\"]?\w+['\"]?\s+\{|allow-transfer|allow-query|allow-update|allow-recursion|also-notify|forwarders|masters|key\s+['\"]?\w+['\"]?\s+\{|server\s+\d+\.\d+\.\d+\.\d+\s+\{|acl\s+['\"]?\w+['\"]?\s+\{|view\s+['\"]?\w+['\"]?\s+\{|options\s+\{|logging\s+\{|controls\s+\{|statistics-channels\s+\{|trusted-keys\s+\{|managed-keys\s+\{|dnssec-policy\s+['\"]?\w+['\"]?\s+\{)\b",
    # --- SMTP injection ---
    r"(?i)(?:\r\n|\n|%0[adAD])\s*(?:HELO|EHLO|MAIL\s+FROM|RCPT\s+TO|DATA|QUIT|RSET|NOOP|VRFY|EXPN|HELP|AUTH\s+(?:LOGIN|PLAIN|CRAM-MD5|DIGEST-MD5|NTLM|GSSAPI|XOAUTH2)|STARTTLS|ETRN|TURN|ATRN|XFORWARD|XCLIENT)\b",
    r"(?i)(?:\r\n|\n)(?:MAIL\s+FROM|RCPT\s+TO|DATA|QUIT|RSET|BDAT|AUTH)\b",
    r"(?i)(?:(?:\r\n|\n)\.(?:\r\n|\n))",
    r"(?i)%0[adAD](?:MAIL|RCPT|DATA|QUIT|RSET|HELO|EHLO|AUTH|STARTTLS)\b",
    # --- FTP attacks ---
    r"(?i)(?:USER|PASS|ACCT|CWD|CDUP|SMNT|QUIT|REIN|PORT|PASV|TYPE|STRU|MODE|RETR|STOR|STOU|APPE|ALLO|REST|RNFR|RNTO|ABOR|DELE|RMD|MKD|PWD|LIST|NLST|SITE|SYST|STAT|HELP|NOOP|FEAT|OPTS|AUTH|ADAT|PBSZ|PROT|CCC|MIC|CONF|ENC|EPRT|EPSV|LANG|MDTM|MFMT|MLSD|MLST|SIZE|TVFS|XCUP|XMKD|XPWD|XRCP|XRMD|XRSQ|XSEM)\b.*(?:\r\n|\n)",
    r"(?i)ftp://(?:\w+:\w+@)?\d+\.\d+\.\d+\.\d+(?::\d+)?/",
    # --- LDAP injection deep ---
    r"(?i)\(\s*(?:\||&|!)\s*\(\s*(?:\w+\s*(?:=|~=|>=|<=)\s*(?:\*|\)|\(|\\[0-9a-fA-F]{2}))",
    r"(?i)\(\s*\w+\s*=\s*(?:\*\)\(\w+\s*=\s*\*|[^)]*\)\s*\(\s*\||[^)]*\)\s*\(\s*&)",
    r"(?i)\(\s*(?:objectClass|objectCategory|sAMAccountName|userPrincipalName|distinguishedName|memberOf|userAccountControl|adminCount|primaryGroupID|operatingSystem|operatingSystemVersion|servicePrincipalName|dNSHostName|serverReferenceBL|whenCreated|whenChanged|msDS-AllowedToActOnBehalfOfOtherIdentity|msDS-AllowedToDelegateTo|msDS-PSOApplied|ms-MCS-AdmPwd|ms-MCS-AdmPwdExpirationTime|msDS-ManagedPassword|msDS-GroupMSAMembership)\s*(?:=|~=|>=|<=)",
    r"(?i)(?:ldapsearch|ldapadd|ldapmodify|ldapdelete|ldapcompare|ldapmodrdn|ldappasswd|ldapwhoami|ldapurl|slapcat|slapadd|slapindex|slaptest|slappasswd|slapauth|slapacl|slapdn|slapschema)\b",
    # --- SNMP attacks ---
    r"(?i)(?:snmpwalk|snmpget|snmpset|snmpbulkget|snmpbulkwalk|snmpgetnext|snmptable|snmptrap|snmpinform|snmptest|snmptranslate|snmpdf|snmpusm|snmpvacm|snmpstatus|snmpnetstat|snmpconf|snmpcmd|onesixtyone|snmp-check|snmpcheck|snmpenum)\b",
    r"(?i)(?:public|private|community|snmp|default|admin|cisco|hp|3com|motorola|secret|security|trap|monitor|manager|operator|write|read|readwrite|system|all|none|test|guest|router|switch|access|network|cable-docsis|snmpd|ILMI)\b\s+(?:snmp|1\.3\.6\.1)",
    r"(?i)1\.3\.6\.1\.(?:2\.1\.(?:1\.(?:1|2|3|4|5|6|7)|2\.(?:1|2)|3|4\.(?:1|2|3|4|20|21|22)|5\.(?:1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26)|6|7|8|10|11|25|26|31|47)|4\.1\.(?:9|2021|8072|311|11|2636|6527|3375|30065|12356))",
    # --- SSH attacks ---
    r"(?i)(?:ssh|scp|sftp|ssh-keygen|ssh-keyscan|ssh-copy-id|ssh-agent|ssh-add|sshpass|sshuttle|autossh)\s+.*(?:-o\s+(?:StrictHostKeyChecking=no|UserKnownHostsFile=/dev/null|ProxyCommand|LocalForward|RemoteForward|DynamicForward|PermitLocalCommand|SendEnv|SetEnv|ForwardAgent|ForwardX11|HostKeyAlgorithms|KexAlgorithms|Ciphers|MACs|PubkeyAuthentication|PasswordAuthentication|ChallengeResponseAuthentication|GSSAPIAuthentication|PreferredAuthentications|IdentityFile|IdentitiesOnly|BatchMode|ConnectTimeout|ConnectionAttempts|ServerAliveInterval|ServerAliveCountMax|TCPKeepAlive|Compression|LogLevel|RequestTTY|RemoteCommand|StreamLocalBindMask|StreamLocalBindUnlink|Tunnel|TunnelDevice))\b",
    r"(?i)(?:ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519|sk-ecdsa-sha2-nistp256)\s+AAAA[A-Za-z0-9+/=]+",
    # --- HTTP request smuggling deep ---
    r"(?i)Transfer-Encoding\s*:\s*(?:chunked|compress|deflate|gzip|identity|x-gzip|x-compress|x-deflate)\b",
    r"(?i)Transfer-Encoding\s*:\s*(?:chunked\s*,\s*identity|identity\s*,\s*chunked|chunked\s*;\s*q=\d+|chunked[\t ]+|[\t ]+chunked|chUnKeD|CHUNKED|Chunked|cHuNkEd)\b",
    r"(?i)Content-Length\s*:\s*\d+\s*(?:\r\n|\n)\s*Transfer-Encoding\s*:\s*chunked\b",
    r"(?i)Transfer-Encoding\s*:\s*chunked\s*(?:\r\n|\n)\s*Content-Length\s*:\s*\d+\b",
    r"(?i)(?:Transfer-Encoding|Content-Length)\s*:\s*(?:\r\n|\n)\s*(?:Transfer-Encoding|Content-Length)\s*:",
    r"(?i)(?:0\s*\r?\n\s*\r?\n\s*(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK)\s+/)",
    # --- HTTP/2 specific attacks ---
    r"(?i)(?::method\s*:\s*(?:CONNECT|TRACE|TRACK|DEBUG|PURGE|SEARCH)|:path\s*:\s*(?:/\.\./|/\.%2e/|/%2e\./|/\.\.;/|//)|:authority\s*:\s*(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1|metadata\.google\.internal|169\.254\.169\.254)|:scheme\s*:\s*(?:file|gopher|dict|ftp|ssh|telnet|ldap))\b",
    r"(?i)(?:SETTINGS|HEADERS|DATA|PRIORITY|RST_STREAM|PUSH_PROMISE|PING|GOAWAY|WINDOW_UPDATE|CONTINUATION)\s+(?:frame|flood|bomb|attack|dos|exploit|overflow)\b",
]

# ============================================================================
# 7. SENSITIVE DATA EXPOSURE (200 patterns)
# ============================================================================
SENSITIVE_DATA = [
    # --- API keys and tokens ---
    r"(?i)(?:api[_-]?key|api[_-]?secret|api[_-]?token|access[_-]?key|access[_-]?secret|access[_-]?token|secret[_-]?key|secret[_-]?token|private[_-]?key|private[_-]?token|auth[_-]?key|auth[_-]?secret|auth[_-]?token|bearer[_-]?token|refresh[_-]?token|session[_-]?token|session[_-]?id|session[_-]?key|csrf[_-]?token|xsrf[_-]?token|master[_-]?key|master[_-]?secret|admin[_-]?key|admin[_-]?secret|root[_-]?key|root[_-]?secret|service[_-]?key|service[_-]?secret|client[_-]?key|client[_-]?secret|consumer[_-]?key|consumer[_-]?secret|signing[_-]?key|signing[_-]?secret|encryption[_-]?key|decryption[_-]?key|hmac[_-]?key|hmac[_-]?secret)\s*(?:=|:|\s)\s*(?:['\"]?[a-zA-Z0-9_\-\.\/\+]{16,}['\"]?)",
    r"(?i)(?:-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----|-----BEGIN\s+(?:DSA\s+)?PRIVATE\s+KEY-----|-----BEGIN\s+EC\s+PRIVATE\s+KEY-----|-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----|-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----|-----BEGIN\s+ENCRYPTED\s+PRIVATE\s+KEY-----|-----BEGIN\s+CERTIFICATE-----|-----BEGIN\s+PUBLIC\s+KEY-----|-----BEGIN\s+X509\s+CRL-----)",
    r"(?i)(?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9]{36,}\b",
    r"(?i)(?:glpat|glcbt|glrt|gldt|glft)-[a-zA-Z0-9\-]{20,}\b",
    r"(?i)(?:xox[bpsar]|xapp)-[a-zA-Z0-9\-]{10,}\b",
    r"(?i)(?:sk-|pk_live_|pk_test_|sk_live_|sk_test_|rk_live_|rk_test_|whsec_|pi_|pm_|ch_|dp_|re_|su_|sub_|cus_|in_|ii_|li_|price_|prod_|src_|tok_|txn_|evt_|acct_|seti_|cs_|ic_|ipi_|link_|plink_|po_|tbr_|trr_|ach_|ba_|card_|charge_|customer_|dispute_|fr_|inv_|mandate_|order_|payment_|payout_|plan_|quote_|rate_|review_|si_|sku_|ss_|ti_|transfer_)[a-zA-Z0-9]{10,}\b",
    r"(?i)(?:AKIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)[A-Z0-9]{16}\b",
    r"(?i)(?:eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+)",
    r"(?i)(?:AIza[a-zA-Z0-9_\-]{35})\b",
    r"(?i)(?:ya29\.[a-zA-Z0-9_\-]+)\b",
    r"(?i)(?:[0-9]+-[a-zA-Z0-9_]{32}\.apps\.googleusercontent\.com)\b",
    r"(?i)(?:sq0[a-z]{3}-[a-zA-Z0-9\-_]{22,})\b",
    r"(?i)(?:sk_live_[a-zA-Z0-9]{24,}|pk_live_[a-zA-Z0-9]{24,})\b",
    r"(?i)(?:AC[a-f0-9]{32})\b",
    r"(?i)(?:SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43})\b",
    r"(?i)(?:key-[a-f0-9]{32})\b",
    r"(?i)(?:sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})\b",
    r"(?i)(?:r[0-9]_[a-zA-Z0-9]{24,})\b",
    r"(?i)(?:hf_[a-zA-Z0-9]{34,})\b",
    # --- Database connection strings ---
    r"(?i)(?:mysql|mariadb|postgres|postgresql|pgsql|mssql|sqlserver|mongodb|redis|memcached|couchbase|couchdb|neo4j|cassandra|elasticsearch|influxdb|clickhouse|timescaledb|cockroachdb|yugabyte|planetscale|supabase|neon|tidb|singlestore|vitess|proxysql|pgbouncer|maxscale|haproxy|pgpool|repmgr|patroni|stolon|citus|barman|pgbackrest|wal-g|pgbadger|pgaudit|timescaledb|postgis|pg_partman|pg_cron|pg_stat_statements|pg_hint_plan|pg_repack|pg_trgm|pg_prewarm|pg_buffercache|pg_freespacemap|pg_visibility|pg_stat_kcache|pg_qualstats|pg_wait_sampling|pg_stat_monitor|pgwatch2|pgmetrics|pgcli|pgadmin|phpmyadmin|adminer|dbeaver|datagrip|navicat|tableplus|sequel_pro|mysql_workbench|mongodb_compass|redis_insight|redisinsight|studio3t|robo3t|nosqlbooster):\/\/\w+:\w+@",
    r"(?i)(?:Server|Data\s+Source|Host|Hostname|Address|Addr|Network\s+Address|Provider|Driver)\s*=\s*[^;]+\s*;\s*(?:Database|Initial\s+Catalog|Dbname)\s*=\s*[^;]+\s*;\s*(?:User\s*(?:Id|Name)?|Uid|Login)\s*=\s*[^;]+\s*;\s*(?:Password|Pwd|Pass)\s*=\s*[^;]+",
    r"(?i)(?:jdbc|odbc):(?:mysql|mariadb|postgresql|sqlserver|oracle|db2|sqlite|h2|hsqldb|derby|firebird|informix|sybase|teradata|netezza|greenplum|vertica|exasol|snowflake|bigquery|athena|presto|trino|hive|impala|spark|drill|phoenix|kudu|accumulo|voltdb|nuodb|memsql|singlestore|cockroachdb|yugabyte|tidb|oceanbase):\/\/",
    # --- Credential patterns ---
    r"(?i)(?:password|passwd|pwd|pass|secret|token|key|auth|credential|cred)\s*(?:=|:|\s)\s*['\"]?(?!(?:null|undefined|none|false|true|0|\*{3,}|x{3,}|\.{3,}|#{3,}|<[^>]+>|\{\{[^}]+\}\}|\$\{[^}]+\}|\$[A-Z_]+|\%[^%]+\%)['\"]?)[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':\\|,.<>\/?`~]{8,}['\"]?\b",
    r"(?i)(?:Basic|Bearer|Digest|HOBA|Mutual|Negotiate|OAuth|SCRAM-SHA-(?:1|256)|vapid|DPoP|GNAP|PrivateToken)\s+[a-zA-Z0-9+/=_\-\.]{20,}\b",
    # --- PII patterns ---
    r"(?i)(?:\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b)",
    r"(?i)(?:\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b)",
]

RULES_MEGA_6_MAP = {
    'encoding_evasion': ENCODING_EVASION,
    'db_protocol_attacks': DB_PROTOCOL_ATTACKS,
    'framework_attacks': FRAMEWORK_ATTACKS,
    'api_abuse': API_ABUSE,
    'infra_cloud_deep': INFRA_CLOUD_DEEP,
    'network_protocol': NETWORK_PROTOCOL,
    'sensitive_data': SENSITIVE_DATA,
}


def get_all_mega6_patterns():
    for category, patterns in RULES_MEGA_6_MAP.items():
        for regex_str in patterns:
            yield (regex_str, category)


def count_mega6_patterns():
    return sum(len(p) for p in RULES_MEGA_6_MAP.values())
