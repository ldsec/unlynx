#!/usr/bin/env bash

PGPASSWORD=prigen2017 psql -v ON_ERROR_STOP=1 -h "localhost" -U "postgres" -p 5434 -d "medcodeployment" <<-EOSQL
BEGIN;
\copy shrine_ont.clinical_sensitive FROM 'files/SHRINE_ONT_CLINICAL_SENSITIVE.csv' ESCAPE '"' DELIMITER ',' CSV;
\copy shrine_ont.clinical_non_sensitive FROM 'files/SHRINE_ONT_CLINICAL_NON_SENSITIVE.csv' ESCAPE '"' DELIMITER ',' CSV;
\copy shrine_ont.genomic_annotations FROM 'files/SHRINE_ONT_GENOMIC_ANNOTATIONS.csv' ESCAPE '"' DELIMITER ',' CSV;
\copy i2b2metadata.sensitive_tagged FROM 'files/I2B2METADATA_SENSITIVE_TAGGED.csv' ESCAPE '"' DELIMITER ',' CSV;
\copy i2b2metadata.non_sensitive_clear FROM 'files/I2B2METADATA_NON_SENSITIVE_CLEAR.csv' ESCAPE '"' DELIMITER ',' CSV;
\copy i2b2demodata.concept_dimension FROM 'files/I2B2DEMODATA_CONCEPT_DIMENSION.csv' ESCAPE '"' DELIMITER ',' CSV;
\copy i2b2demodata.patient_mapping FROM 'files/I2B2DEMODATA_PATIENT_MAPPING.csv' ESCAPE '"' DELIMITER ',' CSV;
\copy i2b2demodata.patient_dimension FROM 'files/I2B2DEMODATA_PATIENT_DIMENSION.csv' ESCAPE '"' DELIMITER ',' CSV;
\copy i2b2demodata.encounter_mapping FROM 'files/I2B2DEMODATA_ENCOUNTER_MAPPING.csv' ESCAPE '"' DELIMITER ',' CSV;
\copy i2b2demodata.visit_dimension FROM 'files/I2B2DEMODATA_VISIT_DIMENSION.csv' ESCAPE '"' DELIMITER ',' CSV;
\copy i2b2demodata.provider_dimension FROM 'files/I2B2DEMODATA_PROVIDER_DIMENSION.csv' ESCAPE '"' DELIMITER ',' CSV;
\copy i2b2demodata.observation_fact FROM 'files/I2B2DEMODATA_OBSERVATION_FACT.csv' ESCAPE '"' DELIMITER ',' CSV;
COMMIT;
EOSQL