CREATE TABLE `devices`(
    `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `device_code` TEXT NOT NULL,
    `mac` TEXT NULL,
    `display_name` TEXT NULL,
    `manufacturer` TEXT NULL,
    `model` TEXT NULL,
    `firmware_version` TEXT NULL,
    `device_type` TEXT NULL,
    `notes` TEXT NULL,
    `created_at` TEXT NULL DEFAULT CURRENT_TIMESTAMP());
ALTER TABLE
    `devices` ADD UNIQUE `devices_device_code_unique`(`device_code`);
ALTER TABLE
    `devices` ADD UNIQUE `devices_mac_unique`(`mac`);
CREATE TABLE `scan_sessions`(
    `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `device_id` INT NOT NULL,
    `target_ip` TEXT NULL,
    `hostname` TEXT NULL,
    `started_at` TEXT NULL DEFAULT CURRENT_TIMESTAMP(), `ended_at` TEXT NULL, `network_name` TEXT NULL, `environment_notes` TEXT NULL, `operator` TEXT NULL, `protocol_version` TEXT NULL);
ALTER TABLE
    `scan_sessions` ADD INDEX `scan_sessions_device_id_index`(`device_id`);
CREATE TABLE `scan_runs`(
    `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `scan_session_id` INT NOT NULL,
    `scan_name` TEXT NULL,
    `command` TEXT NULL,
    `stdout_text` TEXT NULL,
    `stderr_text` TEXT NULL,
    `exit_code` INT NULL,
    `started_at` TEXT NULL DEFAULT CURRENT_TIMESTAMP(), `ended_at` TEXT NULL, `tool_name` TEXT NULL, `tool_version` TEXT NULL, `parsed_data_json` TEXT NULL);
ALTER TABLE
    `scan_runs` ADD INDEX `scan_runs_scan_session_id_index`(`scan_session_id`);
CREATE TABLE `aggregated_inputs`(
    `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `scan_session_id` INT NOT NULL,
    `variant_name` TEXT NULL,
    `parser_version` TEXT NULL,
    `input_payload_json` TEXT NULL,
    `created_at` TEXT NULL DEFAULT CURRENT_TIMESTAMP(), `notes` TEXT NULL);
ALTER TABLE
    `aggregated_inputs` ADD INDEX `aggregated_inputs_scan_session_id_index`(`scan_session_id`);
CREATE TABLE `prompts`(
    `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `prompt_name` TEXT NULL,
    `prompt_version` TEXT NULL,
    `prompt_text` TEXT NOT NULL,
    `created_at` TEXT NULL DEFAULT CURRENT_TIMESTAMP(), `notes` TEXT NULL);
CREATE TABLE `experiments`(
    `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `name` TEXT NOT NULL,
    `model_name` TEXT NULL,
    `model_version` TEXT NULL,
    `prompt_id` INT NULL,
    `temperature` FLOAT(53) NULL,
    `top_p` FLOAT(53) NULL,
    `seed` INT NULL,
    `notes` TEXT NULL,
    `created_at` TEXT NULL DEFAULT CURRENT_TIMESTAMP());
CREATE TABLE `model_runs`(
    `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `aggregated_input_id` INT NOT NULL,
    `experiment_id` INT NULL,
    `prompt_id` INT NULL,
    `trial_number` INT NULL,
    `model_name` TEXT NULL,
    `model_version` TEXT NULL,
    `temperature` FLOAT(53) NULL,
    `top_p` FLOAT(53) NULL,
    `max_tokens` INT NULL,
    `seed` INT NULL,
    `conversation_history_json` TEXT NULL,
    `raw_output_text` TEXT NULL,
    `parsed_output_json` TEXT NULL,
    `started_at` TEXT NULL DEFAULT CURRENT_TIMESTAMP(), `ended_at` TEXT NULL, `status` TEXT NULL DEFAULT 'pending', `error_text` TEXT NULL);
ALTER TABLE
    `model_runs` ADD INDEX `model_runs_aggregated_input_id_index`(`aggregated_input_id`);
ALTER TABLE
    `model_runs` ADD INDEX `model_runs_experiment_id_index`(`experiment_id`);
CREATE TABLE `ground_truth`(
    `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `device_id` INT NOT NULL,
    `true_vendor` TEXT NULL,
    `true_product` TEXT NULL,
    `true_firmware_version` TEXT NULL,
    `accepted_cpes_json` TEXT NULL,
    `rubric_version` TEXT NULL,
    `label_status` TEXT NULL,
    `notes` TEXT NULL,
    `created_at` TEXT NULL DEFAULT CURRENT_TIMESTAMP(), `updated_at` TEXT NULL DEFAULT CURRENT_TIMESTAMP());
CREATE TABLE `scores`(
    `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `model_run_id` INT NOT NULL,
    `ground_truth_id` INT NOT NULL,
    `score_type` TEXT NULL,
    `exact_match` INT NULL,
    `partial_credit_level` FLOAT(53) NULL,
    `predicted_vendor` TEXT NULL,
    `predicted_product` TEXT NULL,
    `predicted_cpes_json` TEXT NULL,
    `score_notes` TEXT NULL,
    `scorer_version` TEXT NULL,
    `created_at` TEXT NULL DEFAULT CURRENT_TIMESTAMP());
ALTER TABLE
    `scan_sessions` ADD CONSTRAINT `scan_sessions_device_id_foreign` FOREIGN KEY(`device_id`) REFERENCES `devices`(`id`);
ALTER TABLE
    `scores` ADD CONSTRAINT `scores_ground_truth_id_foreign` FOREIGN KEY(`ground_truth_id`) REFERENCES `ground_truth`(`id`);
ALTER TABLE
    `ground_truth` ADD CONSTRAINT `ground_truth_device_id_foreign` FOREIGN KEY(`device_id`) REFERENCES `devices`(`id`);
ALTER TABLE
    `experiments` ADD CONSTRAINT `experiments_prompt_id_foreign` FOREIGN KEY(`prompt_id`) REFERENCES `prompts`(`id`);
ALTER TABLE
    `scan_runs` ADD CONSTRAINT `scan_runs_scan_session_id_foreign` FOREIGN KEY(`scan_session_id`) REFERENCES `scan_sessions`(`id`);
ALTER TABLE
    `model_runs` ADD CONSTRAINT `model_runs_experiment_id_foreign` FOREIGN KEY(`experiment_id`) REFERENCES `experiments`(`id`);
ALTER TABLE
    `model_runs` ADD CONSTRAINT `model_runs_prompt_id_foreign` FOREIGN KEY(`prompt_id`) REFERENCES `prompts`(`id`);
ALTER TABLE
    `scores` ADD CONSTRAINT `scores_model_run_id_foreign` FOREIGN KEY(`model_run_id`) REFERENCES `model_runs`(`id`);
ALTER TABLE
    `aggregated_inputs` ADD CONSTRAINT `aggregated_inputs_scan_session_id_foreign` FOREIGN KEY(`scan_session_id`) REFERENCES `scan_sessions`(`id`);
ALTER TABLE
    `model_runs` ADD CONSTRAINT `model_runs_aggregated_input_id_foreign` FOREIGN KEY(`aggregated_input_id`) REFERENCES `aggregated_inputs`(`id`);
