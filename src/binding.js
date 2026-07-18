// Copyright 2024 Tether Operations Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * Native binding for secure keychain/keystore operations.
 * @module bare-signer/binding
 */
import { fileURLToPath } from 'bare-url'
import path from 'bare-path'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

export default import.meta.addon(path.join(__dirname, '..'))
