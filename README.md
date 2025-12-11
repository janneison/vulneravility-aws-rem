# Remediación automática de controles de Security Hub

Lambda escrita en Python para remediar de forma automática los controles de Security Hub:

- `DynamoDB.1`: habilita autoescalado para tablas en modo aprovisionado.
- `DynamoDB.2`: habilita Point-In-Time Recovery (PITR).
- `DynamoDB.6`: habilita protección contra eliminación.
- `SNS.4`: elimina acceso público en políticas de temas SNS reemplazando `*` por el `AccountId`.
- `SQS.3`: elimina acceso público en políticas de colas SQS reemplazando `*` por el `AccountId`.
- `KMS.5`: elimina acceso público en políticas de claves KMS reemplazando `*` por el `AccountId`.

La función espera eventos provenientes de Security Hub (por ejemplo desde un Custom Action de EventBridge) e intenta remediar cada `finding` recibido.

## Estructura

- `lambda/lambda_function.py`: lógica de remediación.
- `lambda/requirements.txt`: dependencias del runtime.
- `terraform/main.tf`: despliegue de la función con IAM mínimo necesario.

## Despliegue con Terraform

1. Exporta tus credenciales AWS o configura el perfil CLI.
2. Entra al directorio `terraform` y ejecuta:

```bash
terraform init
terraform apply -auto-approve
```

Variables útiles:

- `aws_region`: región destino (por defecto `us-east-1`).
- `lambda_name`: nombre de la función (por defecto `security-hub-remediator`).
- `default_min_capacity` / `default_max_capacity`: límites para autoescalado de DynamoDB.
- `dynamodb_scaling_role_arn`: si usas un rol de Application Auto Scaling existente, proporciónalo aquí.

El paquete Lambda se genera automáticamente con `archive_file` a partir del contenido de `../lambda`.

## Funcionamiento

La función analiza cada `finding` y, según el `SecurityControlId` y el tipo de recurso, aplica la acción correspondiente:

- **DynamoDB.1**: si la tabla está en modo aprovisionado, asegura throughput inicial y crea políticas de autoescalado para lectura y escritura.
- **DynamoDB.2**: habilita PITR con `UpdateContinuousBackups`.
- **DynamoDB.6**: habilita `DeletionProtectionEnabled` en la tabla.
- **SNS.4 / SQS.3 / KMS.5**: obtiene la política actual, reemplaza Principals públicos (`*`) por el ARN `arn:aws:iam::<account_id>:root` y elimina condiciones basadas en IP que otorguen acceso abierto.

Cada acción exitosa agrega una entrada en `remediationResults` indicando el recurso y la operación realizada.
