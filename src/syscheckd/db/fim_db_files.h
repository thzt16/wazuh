/**
 * @file fim_db_files.h
 * @brief Definition of FIM database for files library.
 * @date 2020-09-9
 *
 * @copyright Copyright (c) 2020 Wazuh, Inc.
 */

#ifndef FIM_DB_FILES_H
#define FIM_DB_FILES_H

#include "fim_db.h"

/**
 * @brief Get checksum of all file_data.
 *
 * @param fim_sql FIM database struct.
 * @param arg CTX object.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_data_checksum(fdb_t *fim_sql, void * arg);

/**
 * @brief Get list of all paths by storing them in a temporal file.
 *
 * @param fim_sql FIM database struct.
 * @param index Type of query.
 * @param fd File where all paths will be stored.
 *
 * @return FIM entry struct on success, NULL on error.
 */
int fim_db_get_multiple_path(fdb_t *fim_sql, int index, FILE *fd);

/**
 * @brief Get all the paths asociated to an inode
 *
 * @param fim_sql FIM databse struct.
 * @param inode Inode.
 * @param dev Device.
 *
 * @return char** An array of the paths asociated to the inode.
 */
char **fim_db_get_paths_from_inode(fdb_t *fim_sql, unsigned long int inode, unsigned long int dev);

/**
 * @brief Insert or update entry data.
 *
 * @param fim_sql FIM database struct.
 * @param entry Entry data to be inserted.
 * @param row_id Row id to insert data.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_insert_data(fdb_t *fim_sql, fim_file_data *entry, int *row_id);

/**
 * @brief Insert or update entry path.
 *
 * @param fim_sql FIM database struct.
 * @param file_path File path.
 * @param entry Entry data to be inserted.
 * @param inode_id Inode id to insert.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_insert_path(fdb_t *fim_sql, const char *file_path, fim_file_data *entry, int inode_id);

/**
 * @brief Insert an entry in the needed tables.
 *
 * @param fim_sql FIM database struct.
 * @param file_path File path.
 * @param new Entry data to be inserted.
 * @param saved Entry with existing data.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_insert(fdb_t *fim_sql, const char *file_path, fim_file_data *new, fim_file_data *saved);

/**
 * @brief Send sync message for all entries.
 *
 * @param fim_sql FIM database struct.
 * @param mutex FIM database's mutex for thread synchronization.
 * @param file Structure of temporal storage which contains all the paths.
 * @param storage 1 Store database in memory, disk otherwise.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_sync_path_range(fdb_t *fim_sql, pthread_mutex_t *mutex,
                            fim_tmp_file *file, int storage);

/**
 * @brief Callback function: Entry checksum calculation.
 *
 * @param fim_sql FIM database struct.
 * @param entry Entry data to calculate checksum.
 * @param storage 1 Store database in memory, disk otherwise.
 * @param arg
 */
void fim_db_callback_calculate_checksum(fdb_t *fim_sql, fim_entry *entry, int storage, void *arg);

/**
 * @brief Calculate checksum of data entries between @start and @top.
 *
 * Said range will be splitted into two and the resulting checksums will
 * be sent as sync messages.
 *
 * @param fim_sql FIM database struct.
 * @param start First entry of the range.
 * @param top Last entry of the range.
 * @param id Sync session counter (timetamp).
 * @param n Number of entries between start and stop.
 * @param mutex FIM database's mutex for thread synchronization.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_data_checksum_range(fdb_t *fim_sql, const char *start, const char *top,
                               long id, int n, pthread_mutex_t *mutex);

/**
 * @brief Count the number of entries between range @start and @top.
 *
 * @param fim_sql FIM database struct.
 * @param start First entry of the range.
 * @param top Last entry of the range.
 * @param counter Pointer which will hold the final count.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_count_range(fdb_t *fim_sql, char *start, char *top, int *counter);

/**
 * @brief Delete entry using file path.
 *
 * @param fim_sql FIM database struct.
 * @param entry Entry data to be removed.
 * @param mutex FIM database's mutex for thread synchronization.
 * @param alert False don't send alert, True send delete alert.
 * @param fim_ev_mode FIM Mode (scheduled/realtime/whodata)
 * @param w_evt Whodata information.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
void fim_db_remove_path(fdb_t *fim_sql, fim_entry *entry, pthread_mutex_t *mutex,
                        __attribute__((unused))void *alert,
                        __attribute__((unused))void *fim_ev_mode,
                        __attribute__((unused))void *w_evt);

/**
 * @brief Get the last/first row from file_entry.
 *
 * @param fim_sql FIM database struct.
 * @param mode FIM_FIRST_ROW or FIM_LAST_ROW.
 * @param path pointer of pointer where the path will be stored.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_row_path(fdb_t *fim_sql, int mode, char **path);

/**
 * @brief Set all entries from database to unscanned.
 *
 * @param fim_sql FIM database struct.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_set_all_unscanned(fdb_t *fim_sql);

/**
 * @brief Set file entry scanned.
 *
 * @param fim_sql FIM database struct.
 * @param path File path.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_set_scanned(fdb_t *fim_sql, char *path);

/**
 * @brief Get all the unscanned files by saving them in a temporal storage.
 *
 * @param fim_sql FIM database struct.
 * @param file Structure of the file which contains all the paths.
 * @param storage 1 Store database in memory, disk otherwise.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_not_scanned(fdb_t * fim_sql, fim_tmp_file **file, int storage);

/**
 * @brief Callback function to send a sync message for a sole entry.
 *
 * @param fim_sql FIM database struct.
 * @param entry Entry data to be inserted.
 * @param mutex FIM database's mutex for thread synchronization.
 * @param alert Unused argument.
 * @param mode Unused argument.
 * @param w_event Unused argument.
 */
void fim_db_callback_sync_path_range(__attribute__((unused)) fdb_t *fim_sql,
                                     fim_entry *entry,
                                     __attribute__((unused)) pthread_mutex_t *mutex,
                                     __attribute__((unused)) void *alert,
                                     __attribute__((unused)) void *mode,
                                     __attribute__((unused)) void *w_event);

/**
 * @brief Delete not scanned entries from database.
 *
 * @param fim_sql FIM database struct.
 * @param file Structure of the file which contains all the paths.
 * @param mutex FIM database's mutex for thread synchronization.
 * @param storage 1 Store database in memory, disk otherwise.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_delete_not_scanned(fdb_t *fim_sql, fim_tmp_file *file, pthread_mutex_t *mutex, int storage);

/**
 * @brief Get path list between @start and @top. (stored in @file).
 *
 * @param fim_sql FIM database struct.
 * @param start First entry of the range.
 * @param top Last entry of the range.
 * @param file  Structure of the storage which contains all the paths.
 * @param storage 1 Store database in memory, disk otherwise.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_path_range(fdb_t *fim_sql, char *start, char *top, fim_tmp_file **file, int storage);

/**
 * @brief Removes a range of paths from the database.
 *
 * The paths are alphabetically ordered.
 * The range is given by start and top parameters.
 *
 * @param fim_sql FIM database struct.
 * @param file Structure of the file which contains all the paths.
 * @param mutex FIM database's mutex for thread synchronization.
 * @param storage 1 Store database in memory, disk otherwise.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_delete_range(fdb_t * fim_sql, fim_tmp_file *file, pthread_mutex_t *mutex, int storage);

/**
 * @brief Remove a range of paths from database if they have a specific monitoring mode.
 *
 * @param fim_sql FIM database struct.
 * @param file Structure of the file which contains all the paths.
 * @param mutex FIM database's mutex for thread synchronization.
 * @param storage 1 Store database in memory, disk otherwise.
 * @param mode FIM mode (scheduled, realtime or whodata)
 * @param w_evt Whodata information
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_process_missing_entry(fdb_t *fim_sql, fim_tmp_file *file, pthread_mutex_t *mutex, int storage,
                                 fim_event_mode mode, whodata_evt * w_evt);

/**
 * @brief Get count of all entries in file_data table.
 *
 * @param fim_sql FIM database struct.
 *
 * @return Number of entries in file_data table.
 */
int fim_db_get_count_file_data(fdb_t * fim_sql);

/**
 * @brief Get count of all entries in file_entry table.
 *
 * @param fim_sql FIM database struct.
 *
 * @return Number of entries in file_entry table.
 */
int fim_db_get_count_file_entry(fdb_t * fim_sql);

#endif /* FIM_DB_FILES_H */