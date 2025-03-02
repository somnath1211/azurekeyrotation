import os
import datetime
import logging
import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient
from azure.keyvault.secrets import SecretClient

# --- Configuration and Initialization ---
SUBSCRIPTION_ID = "1ceae394-3739-48ac-a29b-5bfced7898c5"
RESOURCE_GROUP_NAME = os.getenv("RESOURCE_GROUP_NAME")  # Optional; limits to a specific resource group if set
KEYVAULT_NAME = "somnathnelge"
ROTATION_THRESHOLD_DAYS = 90  # Days after which a key is considered stale

# Set up credentials and clients
credential = DefaultAzureCredential()
storage_client = StorageManagementClient(credential, SUBSCRIPTION_ID)
kv_client = SecretClient(vault_url=f"https://{KEYVAULT_NAME}.vault.azure.net/", credential=credential)

# --- Helper Functions ---

def get_resource_group_from_id(resource_id):
    """
    Extract the resource group from the storage account's resource id.
    Expected format: /subscriptions/<subId>/resourceGroups/<rg>/providers/Microsoft.Storage/storageAccounts/<account>
    """
    try:
        parts = resource_id.split('/')
        rg_index = parts.index("resourceGroups") + 1
        return parts[rg_index]
    except Exception as e:
        logging.error(f"Error extracting resource group from id '{resource_id}': {e}")
        return None

def get_storage_accounts():
    """Fetch all storage accounts from the subscription or a specified resource group."""
    if RESOURCE_GROUP_NAME:
        logging.info(f"Fetching storage accounts in resource group: {RESOURCE_GROUP_NAME}")
        return storage_client.storage_accounts.list_by_resource_group(RESOURCE_GROUP_NAME)
    logging.info("Fetching storage accounts in subscription")
    return storage_client.storage_accounts.list()

def get_last_rotation_date(storage_account_name, key_name):
    """
    Retrieve the last rotation date from Key Vault for a given key.
    Secret name format: <storage_account_name>-<key_name> (all in lowercase)
    """
    secret_name = f"{storage_account_name}-{key_name.lower()}"
    try:
        secret = kv_client.get_secret(secret_name)
        logging.info(f"Found secret '{secret_name}' last updated on {secret.properties.updated_on}")
        return secret.properties.updated_on.date()
    except Exception as e:
        logging.info(f"Secret '{secret_name}' not found or error retrieving it: {e}")
        return None

def rotate_storage_account_keys(storage_account):
    """
    For the given storage account, checks both keys and rotates only the key that is older than the threshold.
    Returns a list of log messages.
    """
    messages = []
    storage_account_name = storage_account.name
    rg = get_resource_group_from_id(storage_account.id)
    if not rg:
        msg = f"Could not determine resource group for '{storage_account_name}'. Skipping."
        logging.error(msg)
        messages.append(msg)
        return messages

    try:
        keys_response = storage_client.storage_accounts.list_keys(rg, storage_account_name)
        keys = keys_response.keys
    except Exception as e:
        msg = f"Error retrieving keys for '{storage_account_name}': {e}"
        logging.error(msg)
        messages.append(msg)
        return messages

    # For each key, determine its age based on Key Vault's last update.
    candidates = []
    for key in keys:
        last_rotation = get_last_rotation_date(storage_account_name, key.key_name)
        if last_rotation:
            age = (datetime.date.today() - last_rotation).days
            messages.append(f"For '{storage_account_name}', {key.key_name} age: {age} days.")
        else:
            # If there's no record, mark it as due for rotation.
            age = ROTATION_THRESHOLD_DAYS + 1
            messages.append(f"No record for '{storage_account_name}' {key.key_name}; marking as due for rotation.")
        candidates.append((key.key_name, age, key.value))

    # Choose the key with the highest age that exceeds the threshold.
    candidate = None
    for key_name, age, key_val in candidates:
        if age >= ROTATION_THRESHOLD_DAYS:
            if candidate is None or age > candidate[1]:
                candidate = (key_name, age, key_val)
    if candidate is None:
        msg = f"Skipping '{storage_account_name}': Both keys have been rotated recently."
        logging.info(msg)
        messages.append(msg)
        return messages

    key_to_rotate = candidate[0]
    msg = f"Rotating '{key_to_rotate}' for '{storage_account_name}' (age: {candidate[1]} days)..."
    logging.info(msg)
    messages.append(msg)

    try:
        # Regenerate the selected key.
        key_result = storage_client.storage_accounts.regenerate_key(
            rg,
            storage_account_name,
            {"key_name": key_to_rotate}
        )
        new_key = None
        for k in key_result.keys:
            if k.key_name.lower() == key_to_rotate.lower():
                new_key = k.value
                break
        if not new_key:
            msg = f"Error: Regenerated key '{key_to_rotate}' for '{storage_account_name}' not found."
            logging.error(msg)
            messages.append(msg)
        else:
            # Update or create the secret in Key Vault.
            secret_name = f"{storage_account_name}-{key_to_rotate.lower()}"
            kv_client.set_secret(secret_name, new_key)
            msg = f"Stored new key in Key Vault: {secret_name}"
            logging.info(msg)
            messages.append(msg)
    except Exception as e:
        error_msg = f"Error rotating key for '{storage_account_name}' ({key_to_rotate}): {e}"
        logging.error(error_msg)
        messages.append(error_msg)
    return messages

def process_rotation():
    """Process all storage accounts and return a detailed log as a string."""
    all_messages = []
    try:
        storage_accounts = get_storage_accounts()
        for account in storage_accounts:
            try:
                msgs = rotate_storage_account_keys(account)
                all_messages.extend(msgs)
            except Exception as inner_e:
                error_msg = f"Error processing storage account '{account.name}': {inner_e}"
                logging.error(error_msg)
                all_messages.append(error_msg)
        if not all_messages:
            all_messages.append("No storage accounts processed.")
    except Exception as e:
        error_message = f"Error during key rotation: {e}"
        logging.error(error_message)
        all_messages.append(error_message)
    return "\n".join(all_messages)

# --- Azure Function App Setup ---
app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

@app.route(route="kyeRotation")
def kyeRotation(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Starting key rotation process via HTTP trigger.')
    result = process_rotation()
    return func.HttpResponse(result, status_code=200)
