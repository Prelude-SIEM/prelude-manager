
drop table Prelude_WebServiceArg;

drop table Prelude_WebService;

drop table Prelude_UserId;

drop table Prelude_User;

drop table Prelude_ToolAlert;

drop table Prelude_Target;

drop table Prelude_Source;

drop table Prelude_ServicePortlist;

drop table Prelude_Service;

drop table Prelude_SNMPService;

drop table Prelude_ProcessEnv;

drop table Prelude_ProcessArg;

drop table Prelude_Process;

drop table Prelude_OverflowAlert;

drop table Prelude_Node;

drop table Prelude_Linkage;

drop table Prelude_Inode;

drop table Prelude_Impact;

drop table Prelude_Heartbeat;

drop table Prelude_FileList;

drop table Prelude_FileAccess;

drop table Prelude_File;

drop table Prelude_DetectTime;

drop table Prelude_CreateTime;

drop table Prelude_CorrelationAlert_Alerts;

drop table Prelude_CorrelationAlert;

drop table Prelude_Confidence;

drop table Prelude_Classification;

drop table Prelude_Assessment;

drop table Prelude_AnalyzerTime;

drop table Prelude_Analyzer;

drop table Prelude_Alert;

drop table Prelude_Address;

drop table Prelude_AdditionalData;

drop table Prelude_Action;

create table Prelude_Action (
alert_ident          INT8                 not null,
description          VARCHAR(255)         null,
category             VARCHAR(18)	  null default 'other' /*,*/
/* constraint PK_PRELUDE_ACTION primary key (alert_ident) */
);

create table Prelude_AdditionalData (
parent_ident         INT8                 not null,
parent_type          VARCHAR(1)           not null,
type                 VARCHAR(10)	  null default 'string',
meaning              VARCHAR(255)         null,
data                 TEXT                 null/*,*/
/*INDEX                (parent_ident,parent_type) null*/
);

create table Prelude_Address (
alert_ident          INT8                 not null,
parent_type          VARCHAR(1)           not null,
parent_ident         INT8                 not null,
category	     VARCHAR(20)	  null default 'unknown',
vlan_name            VARCHAR(255)         null,
vlan_num             INT4                 null,
address              VARCHAR(255)         not null,
netmask              VARCHAR(255)         null/*,*/
/* INDEX                (address)            null */
);

create table Prelude_Alert (
ident                INT8                 not null,
constraint PK_PRELUDE_ALERT primary key (ident) 
);

create table Prelude_Analyzer (
parent_ident         INT8                 not null,
parent_type          VARCHAR(1)           not null,
ident                INT8                 not null default 1,
analyzerid           INT8                 not null,
manufacturer         VARCHAR(255)         null,
model                VARCHAR(255)         null,
version              VARCHAR(255)         null,
class                VARCHAR(255)         null,
ostype               VARCHAR(255)         null,
osversion            VARCHAR(255)         null,
constraint PK_PRELUDE_ANALYZER primary key (parent_ident, parent_type, ident)
);

create table Prelude_AnalyzerTime (
parent_ident         INT8                 not null,
parent_type          VARCHAR(1)           not null,
time                 VARCHAR(20)          not null,
ntpstamp             VARCHAR(21)          not null,
constraint PK_PRELUDE_ANALYZERTIME primary key (parent_ident, parent_type)
);

create table Prelude_Assessment (
alert_ident          INT8                 not null,
constraint PK_PRELUDE_ASSESSMENT primary key (alert_ident)
);

create table Prelude_Classification (
alert_ident          INT8                 not null,
origin               VARCHAR(16)	  null default 'unknown',
name                 VARCHAR(255)         not null,
url                  VARCHAR(255)         not null /*,*/
/* INDEX                (alert_ident)        null */
);

create table Prelude_Confidence (
alert_ident          INT8                 not null,
confidence           FLOAT8               null,
rating               VARCHAR(8) 	  null default 'numeric',
constraint PK_PRELUDE_CONFIDENCE primary key (alert_ident)
);

create table Prelude_CorrelationAlert (
ident                INT8                 not null,
name                 VARCHAR(255)         not null,
constraint PK_PRELUDE_CORRELATIONALERT primary key (ident)
);

create table Prelude_CorrelationAlert_Alerts (
ident                INT8                 not null,
alert_ident          INT8                 not null,
constraint PK_PRELUDE_CORRELATIONALERT_AL primary key (ident, alert_ident)
);

create table Prelude_CreateTime (
parent_ident         INT8                 not null,
parent_type          VARCHAR(1)           not null,
time                 VARCHAR(20)             not null,
ntpstamp             VARCHAR(21)          not null,
constraint PK_PRELUDE_CREATETIME primary key (parent_ident, parent_type)
);

create table Prelude_DetectTime (
alert_ident          INT8                 not null,
time                 VARCHAR(20)          not null,
ntpstamp             VARCHAR(21)          not null,
constraint PK_PRELUDE_DETECTTIME primary key (alert_ident)
);

create table Prelude_File (
alert_ident          INT8                 not null,
target_ident         INT8                 not null,
ident		     INT8		  not null,
path                 VARCHAR(255)         not null,
name                 VARCHAR(255)         not null,
category             VARCHAR(9)		  null,
create_time          DATE                 null,
modify_time          DATE                 null,
access_time          DATE                 null,
data_size            INT4                 null,
disk_size            INT4                 null /*,*/
/* INDEX                (alert_ident,target_ident) null*/
);

create table Prelude_FileAccess (
alert_ident          INT8                 not null,
target_ident         INT8                 not null,
file_ident	     INT8		  not null,
path_file            VARCHAR(255)         not null,
name_file            VARCHAR(255)         not null,
userId_ident         INT4                 not null,
permission           VARCHAR(255)         null /*,*/
/* INDEX                (alert_ident,target_ident) null*/
);

create table Prelude_FileList (
alert_ident          INT8                 not null,
target_ident         INT8                 not null,
constraint PK_PRELUDE_FILELIST primary key (alert_ident, target_ident)
);

create table Prelude_Heartbeat (
ident                INT8                 not null,
constraint PK_PRELUDE_HEARTBEAT primary key (ident)
);

create table Prelude_Impact (
alert_ident          INT8                 not null,
description          VARCHAR(255)         null,
severity             VARCHAR(7)		  null,
completion           VARCHAR(9)		  null,
type                 VARCHAR(6)		  null default 'other',
constraint PK_PRELUDE_IMPACT primary key (alert_ident)
);

create table Prelude_Inode (
alert_ident          INT8                 not null,
target_ident         INT8                 not null,
file_ident	     INT8		  not null,
path_file            VARCHAR(255)         not null,
name_file            VARCHAR(255)         not null,
change_time          DATE                 null,
number               INT4                 null,
major_device         INT4                 null,
minor_device         INT4                 null,
c_major_device       INT4                 null,
c_minor_device       INT4                 null/*,*/
/* INDEX                (alert_ident,target_ident) null */
);

create table Prelude_Linkage (
alert_ident          INT8                 not null,
target_ident         INT8                 not null,
file_ident	     INT8		  not null,
name                 VARCHAR(255)         not null,
path                 VARCHAR(255)         not null,
category             VARCHAR(14)	  not null /*,*/
/* INDEX                (alert_ident,target_ident) null*/
);

create table Prelude_Node (
alert_ident          INT8                 not null,
parent_type          VARCHAR(1)           not null,
parent_ident         INT8                 not null,
category             VARCHAR(9)		  null default 'unknown',
location             VARCHAR(255)         null,
name                 VARCHAR(255)         null,
constraint PK_PRELUDE_NODE primary key (alert_ident, parent_type, parent_ident)
);

create table Prelude_OverflowAlert (
alert_ident          INT8                 not null,
program              VARCHAR(255)         not null,
size                 INT4                 null,
buffer               TEXT                 null,
constraint PK_PRELUDE_OVERFLOWALERT primary key (alert_ident)
);

create table Prelude_Process (
alert_ident          INT8                 not null,
parent_type          VARCHAR(1)           not null,
parent_ident         INT8                 not null,
name                 VARCHAR(255)         not null,
pid                  INT4                 null,
path                 VARCHAR(255)         null,
constraint PK_PRELUDE_PROCESS primary key (alert_ident, parent_type, parent_ident)
);

create table Prelude_ProcessArg (
alert_ident          INT8                 not null,
parent_type          VARCHAR(1)           not null,
parent_ident         INT8                 not null,
arg                  VARCHAR(255)         null/*,*/
/* INDEX                (alert_ident,parent_type,parent_ident) null */
);

create table Prelude_ProcessEnv (
alert_ident          INT8                 not null,
parent_type          VARCHAR(1)           not null,
parent_ident         INT8                 not null,
env                  VARCHAR(255)         /*null,*/
/* INDEX                (alert_ident,parent_type,parent_ident) null */
);

create table Prelude_SNMPService (
alert_ident          INT8                 not null,
parent_type          VARCHAR(1)           not null,
parent_ident         INT8                 not null,
pg_oid                  VARCHAR(255)         null,
community            VARCHAR(255)         null,
command              VARCHAR(255)         null,
constraint PK_PRELUDE_SNMPSERVICE primary key (alert_ident, parent_type, parent_ident)
);

create table Prelude_Service (
alert_ident          INT8                 not null,
parent_type          VARCHAR(1)           not null,
parent_ident         INT8                 not null,
name                 VARCHAR(255)         null,
port                 INT4                 null,
protocol             VARCHAR(255)         null,
constraint PK_PRELUDE_SERVICE primary key (alert_ident, parent_type, parent_ident)
);

create table Prelude_ServicePortlist (
alert_ident          INT8                 not null,
parent_type          VARCHAR(1)           not null,
parent_ident         INT8                 not null,
portlist	     VARCHAR(255)         not null /*,*/
/* INDEX                (alert_ident,parent_type,parent_ident) null */
);

create table Prelude_Source (
alert_ident          INT8                 not null,
ident                INT4                 not null,
spoofed              VARCHAR(8)		  null default 'unknown',
interface            VARCHAR(255)         null,
constraint PK_PRELUDE_SOURCE primary key (alert_ident, ident)
);

create table Prelude_Target (
alert_ident          INT8                 not null,
ident                INT4                 not null,
decoy                VARCHAR(8)		  null default 'unknown',
interface            VARCHAR(255)         null,
constraint PK_PRELUDE_TARGET primary key (alert_ident, ident)
);

create table Prelude_ToolAlert (
alert_ident          INT8                 not null,
name                 VARCHAR(255)         not null,
command              VARCHAR(255)         null,
constraint PK_PRELUDE_TOOLALERT primary key (alert_ident)
);

create table Prelude_User (
alert_ident          INT8                 not null,
parent_type          VARCHAR(1)           not null,
parent_ident         INT8                 not null,
category             VARCHAR(12)	  null default 'unknown',
constraint PK_PRELUDE_USER primary key (alert_ident, parent_type, parent_ident)
);

create table Prelude_UserId (
alert_ident          INT8                 not null,
parent_type          VARCHAR(1)           not null,
parent_ident         INT8                 not null,
ident                INT4                 not null,
type                 VARCHAR(14)	  null default 'original-user',
name                 VARCHAR(255)         null,
number               VARCHAR(255)         null,
constraint PK_PRELUDE_USERID primary key (alert_ident, parent_type, parent_ident, ident)
);

create table Prelude_WebService (
alert_ident          INT8                 not null,
parent_type          VARCHAR(1)           not null,
parent_ident         INT8                 not null,
url                  VARCHAR(255)         not null,
cgi                  VARCHAR(255)         null,
http_method          VARCHAR(255)         null,
constraint PK_PRELUDE_WEBSERVICE primary key (alert_ident, parent_type, parent_ident)
);

create table Prelude_WebServiceArg (
alert_ident          INT8                 not null,
parent_type          VARCHAR(1)           not null,
parent_ident         INT8                 not null,
arg                  VARCHAR(255)         null /*,*/
/*INDEX                (alert_ident,parent_type,parent_ident) null*/
);

