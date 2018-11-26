/*
 * Copyright (c) 2016-2018. Uniquid Inc. or its affiliates. All Rights Reserved.
 *
 * License is in the "LICENSE" file accompanying this file.
 * See the License for the specific language governing permissions and limitations under the License.
 */

 /**
 * @file   UID_persistence.h
 *
 * @date   16/feb/2017
 * @author M. Palumbi
 */



char *load_tprv(char *privateKey, size_t size);
void store_tprv(char *privateKey);
