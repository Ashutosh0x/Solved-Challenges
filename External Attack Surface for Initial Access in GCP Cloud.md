Google Cloud Platform (GCP) Services Overview
GCP Bucket
A GCP bucket refers to a Google Cloud Storage bucket, a fundamental component of Google Cloud Platform's object storage service. It allows you to store and access large amounts of unstructured data and scales as needed.

GCP BigQuery Dataset
A GCP BigQuery dataset is a container that organizes and manages tables and views in Google BigQuery, Google's fully managed, serverless data warehouse service. It helps in running SQL-like queries on large datasets efficiently.

GCP KMS Keys
GCP KMS (Key Management Service) keys are cryptographic keys used to manage encryption and decryption in Google Cloud Platform. They work with other GCP services for data encryption, securing data at rest and in transit.

GCP VM Image
A GCP VM image is a virtual machine image used to create instances in Google Compute Engine. It contains the operating system and additional software pre-installed, essential for deploying standardized environments.

GCP SQL Database Instances
GCP SQL database instances are managed relational database services provided by Google Cloud, supporting popular database engines like MySQL, PostgreSQL, and SQL Server. They offer management, scalability, and security benefits.

## Sample Public URLs

|GCP Service|Sample Public URL|
|---|---|
|GCP Bucket|[http://BUCKET_NAME.storage.googleapis.com/OBJECT_NAME](http://BUCKET_NAME.storage.googleapis.com/OBJECT_NAME) OR [http://storage.googleapis.com/BUCKET_NAME/OBJECT_NAME](http://storage.googleapis.com/BUCKET_NAME/OBJECT_NAME)|
|Cloud Functions|https://<region>-<project-gcp-name>.cloudfunctions.net/<func_name>|
|Compute Engine (VM Instance)|https://compute.googleapis.com/compute/v1/projects/{project}/zones/{zone}/instances/{instance}|
|GCP BigQuery|https://bigquery.googleapis.com/bigquery/v2/projects/{project}/datasets/{dataset}/tables/{table}|
|GCP Cloud Pub/Sub|https://pubsub.googleapis.com/v1/projects/{project}/topics/{topic}|

### Scenario 1: OSINT
GCP Bucket CLI-based Recon


```bash
./cloud_enum.py -k <KEYWORD> --disable-azure --disable-aws
./s3scanner -bucket <KEYWORD> -enumerate -json
```
- Cloud Enum
- S3 Scanner
- GCP Bucket
Bucket search:

https://osint.sh/buckets
https://buckets.grayhatwarfare.com
https://builtwith.com/
https://s3browser.com/
Dorks:

- GitHub Dorks: `site:storage.googleapis.com`
Web-based Recon:

More Google Dorks: site:console.cloud.google.com/storage/browser/_details
GCP BigQuery Dataset
Dorks:

- Google Dorks: `site:cloud.google.com "BigQuery dataset"`
Web-based Recon:

`site:*.cloud.google.com inurl:bigquery "dataset"`
GCP KMS Keys
Dorks:

Google Dorks: `inurl:"keyRing" inurl:"cryptoKey" intext:"Google Cloud"`
Web-based Recon:

- `site:cloud.google.com "KMS" "keys"`
- `filetype:pdf "kms" "keyRing" "cryptoKey"`
- `filetype:pdf "bindings" "role" "serviceAccount" "kms"`
GCP VM Image
Dorks:

Google Dorks: `intitle:"Google Cloud" inurl:"compute" "vm image"`
Web-based Recon:

`site:github.com "google cloud" "vm image" filetype:yaml OR filetype:json`
`inurl:"compute/docs/images" intitle:"Google Cloud"
GitHub Dorks:`

- ``filename:*.yaml "image:" "gce-vm-image"``
- `filename:*.tf "source_image" "google_compute_instance"`
- `filename:*.yml "hosts:" "tasks:" "google_compute"`
GCP SQL Database Instances
Dorks:

Google Dorks: `intitle:"Google Cloud SQL" inurl:docs "instance"`
Web-based Recon:

`site:*.com filetype:sql "google_cloud_sql"`
`site:github.com "google cloud sql" filename:*.tf`
GitHub Dorks:

`filename:.env "sql_password" OR "db_password"`
`filename:credentials.json "type":"service_account" "sqladmin.googleapis.com"`
`filename:*.json "databaseVersion" "google_sql_database_instance"`
### Scenario 2: Unauthenticated Enumeration
- GCP Bucket Recon
CLI-based Recon:

```bash
gcloud projects list --format="table(projectId)"
gsutil ls -p <Project_ID>
gsutil iam get gs://cc-webdata-bucket/ --format=json | jq '.bindings[].members[]'
```
Output: If "allUsers" or "allAuthenticatedUsers" appears, the bucket is publicly accessible.

- BigQuery Dataset Recon
CLI-based Recon:


```bash
bq ls --project_id <PROJECT_ID> --format=pretty
bq show --format=pretty <DATASET_ID>
```
Output: If roles use "allUsers" or "allAuthenticatedUsers", the dataset is publicly accessible.

- KMS Keys Recon
CLI-based Recon:


```bash
gcloud kms keyrings list --location=global
gcloud kms keys list --keyring=<KEYRING> --location=global --format="table(name)"
gcloud kms keys get-iam-policy <KEY> --format=json | jq '.bindings[].members[]'
```
Output: If "allUsers" or "allAuthenticatedUsers" appears, the KMS key is publicly accessible.

- VM Image Recon
CLI-based Recon:


```bash
gcloud projects list --format="table(projectId)"
gcloud compute images list --project <project_id> --no-standard-images --format="table(name)"
gcloud compute images get-iam-policy <IMAGE_NAME> --format=json
```
Output: If "allAuthenticatedUsers" appears, the VM disk image is publicly shared.

- SQL Database Instances Recon
CLI-based Recon:


```bash
gcloud projects list --format="table(projectId)"
gcloud sql instances list --project <PROJECT_ID> --format="(NAME)"
gcloud sql instances describe <INSTANCE_NAME> --format=json | jq '.settings.ipConfiguration.authorizedNetworks[].value'
```
Output: If the output contains "0.0.0.0/0", the database instance is publicly accessible.