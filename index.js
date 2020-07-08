const { DataSource } = require('apollo-datasource');
const firebase = require('firebase');
const admin = require('firebase-admin');
require('firebase/firestore');

const tryParseBool = (value) => {
  try {
    if (value.toLowerCase() === "true") return true;
    if (value.toLowerCase() === "false") return false;
    return value;
  } catch (e) {
    return value;
  }
};

const reservedClaims = ["acr", "amr", "at_hash", "aud", "auth_time", "azp", "cnf", "c_hash", "exp", "firebase", "iat", "iss", "jti", "nbf", "nonce", "sub"];

class FirebaseDataSource extends DataSource {

  constructor({ firebaseOptions, serviceAccount, databaseURL }) {
    super();

    this.context;
    this.cache;
    this.activeUser;

    if (!firebase.apps.length) {
      firebase.initializeApp(firebaseOptions);
    };

    if (!admin.apps.length) {
      admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
        databaseURL
      });
    };

    if (!this.db) {
      this.db = firebase.firestore();
    };

    if (!this.auth) {
      this.auth = firebase.auth;
    };

    this.defaultCustomClaims = {
      admin: false
    };

    this.defaultFilterOptions = {
      orderBy: "",
      sortOrder: "asc",
      where: [
        { field: "", operator: "", value: "" }
      ]
    };

    this.defaultPageOptions = {
      pageSize: 20,
      direction: "forward",
      cursor: []
    };

  };

  async initialize(config) {
    this.context = config.context;
    this.activeUser = await this.retrieveUserFromRequest(config.context.request);
  };

  /* HELPER FUNCTIONS */

  /** Get the active user's credentials from the request object.
   *
   * @webonly
   *
   * @example
   * ```javascript
   * 
   *  const users = await retrieveUserFromRequest(req);
   * 
   * ```
   *
   * @param req the request object.
   * @return active user.
   */
  async retrieveUserFromRequest(req) {
    var errors = [];
    var activeUser = {};
    const token = req.headers['x-token'];
    if (token) {
      var activeUser = await this.retrieveUserFromToken(token);
    } else {
      errors.push(new Error("The request has no token in the headers to verify."));
    };
    if (errors.length > 0) activeUser = { errors };
    return activeUser;
  };

  /** Get the active user's credentials from a token.
   *
   * @webonly
   *
   * @example
   * ```javascript
   * 
   *  const users = await retrieveUserFromToken(token);
   * 
   * ```
   *
   * @param token the authentication token object.
   * @return active user.
   */
  async retrieveUserFromToken(token) {
    var errors = [];
    var activeUser = {};
    if (token) {
      try {
        const userCredential = await this.auth().signInWithCustomToken(token);
        const idTokenResult = await userCredential.user.getIdTokenResult();
        var claims;
        for (const key in idTokenResult.claims) {
          if (reservedClaims.indexOf(key) === -1) {
            claims = { ...claims, [key]: tryParseBool(idTokenResult.claims[key]) };
          };
        };
        if (!('admin' in claims)) claim = { ...claims, admin: false };
        activeUser = {
          ...userCredential.user.toJSON(),
          customClaims: claims,
          token
        };

      } catch (e) {
        errors.push(new Error('Could not validate user from token.', e));
      };
    } else {
      errors.push(new Error("No token has been supplied to verify."));
    };
    if (errors.length > 0) activeUser = { errors };
    return activeUser;
  };

  /* AUTH AND ADMIN FUNCTIONS */

  /** Retrieve a list of users.
   *
   * @webonly
   *
   * @example
   * ```javascript
   * 
   *  const args = {
   *    pageSize: 20,
   *    pageToken: null
   *  }
   *  const users = await getPageOfUsers(args);
   * 
   * ```
   *
   * @param args An object of arguments.
   * @return page object of users.
   */
  async getPageOfUsers(args) {
    if (this.activeUser.errors && this.activeUser.errors.length > 0) {
      throw new Error("User authentication error", this.activeUser.errors);
    };
    if (this.activeUser && this.activeUser.customClaims.admin) {
      const { pageSize, pageToken } = args;
      const listUsersResult = await admin.auth().listUsers(pageSize || 50, pageToken);
      listUsersResult.users.forEach(user => {
        for (const property in user.customClaims) {
          user.customClaims[property] = tryParseBool(user.customClaims[property]);
        }
      });
      return {
        users: listUsersResult.users,
        pageSize: listUsersResult.pageSize || pageSize,
        pageToken: listUsersResult.pageToken
      };
    }
  };

  /** Sign up a new user in firestore with username and password.
   *
   * @webonly
   *
   * @example
   * ```javascript
   * 
   *  const args = {
   *    email: "user@mail.com",
   *    password: "AStrongPassword"
   *  }
   * 
   * ```
   *
   * @param args An object of arguments.
   * @return active user.
   */
  async userSignUp(args) {
    const {
      email,
      password
    } = args;

    try {
      var secret = password;
      const userCredential = await this.auth().createUserWithEmailAndPassword(email, secret);
      const token = await admin.auth().createCustomToken(userCredential.user.uid, this.defaultCustomClaims);
      var user = userCredential.user.toJSON();
      admin.auth().setCustomUserClaims(user.uid, this.defaultCustomClaims);
      var activeUser = {
        ...user,
        token,
        customClaims: this.defaultCustomClaims
      };
      this.activeUser = activeUser;
      return activeUser;
    } catch (e) {
      console.log('Failed to sign up user', args, e);
      throw e;
    }
  };

  /** Sign user in to the firestore with username and password.
   *
   * @webonly
   *
   * @example
   * ```javascript
   * 
   *  const args = {
   *    email: "user@mail.com",
   *    password: "AStrongPassword"
   *  }
   *  const user = await userSignIn(args);
   * 
   * ```
   *
   * @param args An object of arguments.
   * @return active user.
   */
  async userSignIn(args) {
    const {
      email,
      password
    } = args;

    try {
      const signIn = await this.auth().signInWithEmailAndPassword(email, password);
      var user = signIn.user.toJSON();
      var idTokenResult = await this.auth().currentUser.getIdTokenResult();
      var claims;
      for (const key in idTokenResult.claims) {
        if (reservedClaims.indexOf(key) === -1) {
          claims = { ...claims, [key]: tryParseBool(idTokenResult.claims[key]) };
        }
      };
      if (!('admin' in claims)) claim = { ...claims, admin: false };
      const token = await admin.auth().createCustomToken(signIn.user.uid, claims);
      var currentUser = {
        ...user,
        token,
        customClaims: claims
      };
      this.activeUser = currentUser;
      return currentUser;
    } catch (e) {
      console.log('Sign in error', e)
      throw e
    }
  };

  /** Force a refresh of the current user's id token.
 *
 * @webonly
 *
 * @example
 * ```javascript
 * 
 *  const users = await refreshIdToken(token);
 * 
 * ```
 *
 * @param token the authentication token object.
 * @return active user.
 */
  async userRefreshIdToken(token) {
    var errors = [];
    var activeUser = {};
    if (token) {

      if (!this.activeUser || this.activeUser.token !== token) {
        throw new Error("The token supplied does not match the  current loggen in user's credentials.");
      }
      try {
        const userCredential = await this.auth().signInWithCustomToken(token);
        const idTokenResult = await userCredential.user.getIdTokenResult();
        var claims;
        for (const key in idTokenResult.claims) {
          if (reservedClaims.indexOf(key) === -1) {
            claims = { ...claims, [key]: tryParseBool(idTokenResult.claims[key]) };
          };
        };
        if (!('admin' in claims)) claim = { ...claims, admin: false };
        var newToken = await admin.auth().createCustomToken(userCredential.user.uid, claims);
        activeUser = {
          ...userCredential.user.toJSON(),
          customClaims: claims,
          token: newToken
        };

      } catch (e) {
        errors.push(new Error('Could not validate user from token.', e));
      };
    } else {
      errors.push(new Error("No token has been supplied to verify."));
    };
    if (errors.length > 0) activeUser = { errors };
    return activeUser;
  };

  /** Update a registered user's info and custom claims.
     *
     * @webonly
     *
     * @example
     * ```javascript
     * 
     *  const user = {
     *    id: "4FVas9I0oTran87Hjf",
     *    email: "user@mail.com",
     *    password: "AStrongPassword", {This will reset an existing password}
     *    displayName: "A Name",
     *    disabled: false
     *    customClaims: {
     *      admin: false,
     *      someRole: true
     *    }
     *  }
     * 
     * ```
     *
     * @param user A user object with custom claims.
     * @return user.
     */
  async updateUserInfo(user) {
    if (this.activeUser.errors && this.activeUser.errors.length > 0) {
      throw new Error("User authentication error", this.activeUser.errors);
    };
    if (this.activeUser && (this.activeUser.customClaims.admin || user.email === this.activeUser.email)) {
      var customClaims = { admin: false };
      var uid = null;
      if (user.uid) {
        uid = user.uid;
        delete user.uid;
      } else {
        throw new Error('User argument must have a uid to change the user info.')
      };
      if (user.customClaims) {
        customClaims = { ...customClaims, ...user.customClaims };
        admin.auth().setCustomUserClaims(uid, customClaims);
        delete user.customClaims;
      }
      if (Object.keys(user).length > 0) {
        user = await admin.auth().updateUser(uid, user);
      }
      return { ...user, uid, customClaims };
    }
  };


  /* FIRESTORE FUNCTIONS */

  /** Add a document to a collection in the firestore.
     *
     * @webonly
     *
     * @example
     * ```javascript
     * 
     *  const args = {
     *    collection: "users",
     *    data: {
     *      firstName: "John",
     *      lastName: "Doe"
     *    }
     *  }
     * 
     * ```
     *
     * @param args An object of arguments.
     * @return javascript object of the document that were added.
     */
  async addDocument(args) {
    const { collection, data } = args;
    if (this.activeUser.errors && this.activeUser.errors.length > 0) {
      throw new Error("User authentication error", this.activeUser.errors);
    };
    if (this.activeUser) {
      const collectionReference = this.db.collection(collection);
      var documentReference;
      if (data.id) {
        documentReference = collectionReference.doc(data.id);
        delete data.id;
        await documentReference.set(data);
      } else {
        documentReference = await collectionReference.add(data);
      }
      const documentSnapshot = await documentReference.get();
      return {
        id: documentSnapshot.id,
        ...documentSnapshot.data()
      };
    } else {
      throw new Error('Not Authorised');
    };
  };

  /** Update a document in a firestore collection.
   *
   * @webonly
   *
   * @example
   * ```javascript
   * 
   *  const args = {
   *    collection: "users",
   *    data: {
   *      id: "3yXfDg56UilE2Wq"
   *      firstName: "John",
   *      lastName: "Doe"
   *    }
   *  }
   * 
   * ```
   *
   * @param args An object of arguments.
   * @return true.
   */
  async updateDocument(args) {
    const { collection, data } = args;
    if (this.activeUser.errors && this.activeUser.errors.length > 0) {
      throw new Error("User authentication error", this.activeUser.errors);
    };
    if (this.activeUser) {
      if (data.id) {
        const documentReference = this.db.collection(collection).doc(data.id);
        delete data.id;
        await documentReference.set(data, { merge: true });
        return true;
      } else {
        throw new Error('The document to update has no id.')
      }
    } else {
      throw new Error('Not Authorised');
    };
  };

  /** Delete a document from a firestore collection.
   *
   * @webonly
   *
   * @example
   * ```javascript
   * 
   *  const args = {
   *    collection: "users",
   *    documentId: "3yXfDg56UilE2Wq"
   *  }
   * 
   * ```
   *
   * @param args An object of arguments.
   * @return true.
   */
  async deleteDocument(args) {
    const { collection, documentId } = args;
    if (this.activeUser.errors && this.activeUser.errors.length > 0) {
      throw new Error("User authentication error", this.activeUser.errors);
    };
    if (this.activeUser) {
      const documentReference = this.db.collection(collection).doc(documentId);
      await documentReference.delete();
      return true;
    } else {
      throw new Error('Not Authorised');
    };
  };

  /** Retrieve a document from a firestore collection.
   *
   * @webonly
   *
   * @example
   * ```javascript
   * 
   *  const args = {
   *    collection: "users",
   *    id: "Van4Tij98lKfbOKP0"
   *  }
   * 
   * ```
   *
   * @param args An object of arguments.
   * @return Object representation of a document.
   */
  async getDocumentById(args) {
    const { collection, id } = args;
    var document = null;
    if (this.activeUser.errors && this.activeUser.errors.length > 0) {
      throw new Error("User authentication error", this.activeUser.errors);
    };
    if (this.activeUser) {
      try {
        const docRef = this.db.collection(collection).doc(id);
        var documentSnapshot = await docRef.get();
        if (documentSnapshot.exists) {
          document = {
            id: documentSnapshot.id,
            ...documentSnapshot.data()
          }
        }
        return document;
      } catch (err) {
        throw new Error('Function getDocumentById failed.', err);
      }
    } else {
      throw new Error('Not Authorised');
    };
  };

  /** Retrieve list of document IDs from a firestore collection.
   *
   * @webonly
   *
   * @example
   * ```javascript
   * 
   *  const args = {
   *    collection: "users"
   *  }
   * 
   * ```
   *
   * @param args An object of arguments.
   * @return Array of documents.
   */
  async listDocuments(args) {
    const { collection, filterArgs } = args;
    const filterOptions = { ...this.defaultFilterOptions, ...filterArgs };
    if (this.activeUser.errors && this.activeUser.errors.length > 0) {
      throw new Error("User authentication error", this.activeUser.errors);
    };
    if (this.activeUser) {
      try {
        var queryRef = this.db.collection(collection);
        if (filterOptions.orderBy && filterOptions.orderBy !== "") {
          const sortOrderArray = filterOptions.sortOrder.split(',');
          filterOptions.orderBy.split(',').map((item, index) => {
            queryRef = queryRef.orderBy(item, sortOrderArray[index] ? sortOrderArray[index] : "asc");
          })
        };
        var querySnapshot = await queryRef.listDocuments();
        var documents = [];
        if (querySnapshot.docs.length > 0) {
          documents = querySnapshot.docs.map(doc => ({
            id: doc.id
          }));
        };
        if (documents.length === 0) throw new Error("No data.");
        return documents;
      } catch (err) {
        throw new Error('Function getDocuments failed.', err);
      }
    } else {
      throw new Error('Not Authorised');
    };
  };

  /** Retrieve data from a firestore collection.
   *
   * @webonly
   *
   * @example
   * ```javascript
   * 
   *  const args = {
   *    collection: "users"
   *  }
   * 
   * ```
   *
   * @param args An object of arguments.
   * @return Array of documents.
   */
  async getDocuments(args) {
    const { collection, filterArgs } = args;
    const filterOptions = { ...this.defaultFilterOptions, ...filterArgs };
    if (this.activeUser.errors && this.activeUser.errors.length > 0) {
      throw new Error("User authentication error", this.activeUser.errors);
    };
    if (this.activeUser) {
      try {
        var queryRef = this.db.collection(collection);
        if (filterOptions.orderBy && filterOptions.orderBy !== "") {
          const sortOrderArray = filterOptions.sortOrder.split(',');
          filterOptions.orderBy.split(',').map((item, index) => {
            queryRef = queryRef.orderBy(item, sortOrderArray[index] ? sortOrderArray[index] : "asc");
          })
        };
        var querySnapshot = await queryRef.get();
        var documents = [];
        if (querySnapshot.docs.length > 0) {
          documents = querySnapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
          }));
        };
        if (documents.length === 0) throw new Error("No data.");
        return documents;
      } catch (err) {
        throw new Error('Function getDocuments failed.', err);
      }
    } else {
      throw new Error('Not Authorised');
    };
  };

  /** Retrieve a page of data from a firestore collection.
   *
   * @webonly
   *
   * @example
   * ```javascript
   * 
   *  const args = {
   *    collection: "users"
   *  }
   * 
   * ```
   *
   * @param args An object of arguments.
   * @return Array of documents.
   */
  async getPageOfDocuments(args) {
    const { collection, filterArgs, pageArgs } = args;
    const filterOptions = { ...this.defaultFilterOptions, ...filterArgs };
    const pageOptions = { ...this.defaultPageOptions, ...pageArgs };
    if (this.activeUser.errors && this.activeUser.errors.length > 0) {
      throw new Error("User authentication error", this.activeUser.errors);
    };
    if (this.activeUser) {
      try {
        var queryRef = this.db.collection(collection);
        if (filterOptions.orderBy && filterOptions.orderBy !== "") {
          const sortOrderArray = filterOptions.sortOrder.split(',');
          filterOptions.orderBy.split(',').map((item, index) => {
            queryRef = queryRef.orderBy(item, sortOrderArray[index] ? sortOrderArray[index] : "asc");
          })
        };
        if (filterOptions.where && filterOptions.where.length > 0) {
          filterOptions.where.forEach(item => {
            if (item.fieldName && item.fieldName !== "" && item.value && item.value !== "" && item.operator) {
              queryRef = queryRef.where(item.fieldName, item.operator !== "" ? item.operator : "", item.value);
            }
          })
        };
        if (pageOptions.cursor && pageOptions.cursor.length > 0) {
          switch (pageOptions.direction) {
            case 'forward':
              var forwardCursor = await this.db.collection(collection)
                .doc(pageOptions.cursor[pageOptions.cursor.length - 1])
                .get();
              queryRef = queryRef
                .startAfter(forwardCursor);
              break;
            case 'back':
              pageOptions.cursor = pageOptions.cursor.slice(0, pageOptions.cursor.length - 2);
              if (pageOptions.cursor.length > 0) {
                var backCursor = await this.db.collection(collection)
                  .doc(pageOptions.cursor[pageOptions.cursor.length - 1])
                  .get();
                queryRef = queryRef
                  .startAfter(backCursor);
              }
              break;
            default:
              break;
          }
        };
        var querySnapshot = await queryRef.limit(pageOptions.pageSize).get();
        var documents = [];
        if (querySnapshot.docs.length > 0) {
          pageOptions.cursor.push(querySnapshot.docs[querySnapshot.docs.length - 1].id);
          documents = querySnapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
          }));
        };
        if (documents.length === 0 && pageOptions.cursor.length) throw new Error("No more paged data.");
        const result = { documents, filterOptions, pageOptions };
        return result;
      } catch (err) {
        throw err;
      }
    } else {
      throw new Error('Not Authorised');
    }
  };

}

module.exports = FirebaseDataSource;

