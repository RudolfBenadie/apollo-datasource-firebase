const { DataSource } = require('apollo-datasource');
const firebase = require('firebase');
const admin = require('firebase-admin');
require('firebase/firestore');

const tryParseBool = (value) => {
  try {
    if (value.toLowerCase() === "true") return true;
    if (value.toLowerCase() === "false") return false;
    return value;
  } catch {
    return value;
  }
};

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
        { field: "", condition: "", value: "" }
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
          if (['iss', 'aud', 'auth_time', 'user_id', 'sub', 'iat', 'exp', 'firebase'].indexOf(key) === -1) {
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
    if (this.activeUser.errors && this.activeUser.errros.length > 0) {
      throw new Error("User authentication error", errors);
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
        if (['iss', 'aud', 'auth_time', 'user_id', 'sub', 'iat', 'exp', 'firebase'].indexOf(key) === -1) {
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
    if (this.activeUser.errors && this.activeUser.errros.length > 0) {
      throw new Error("User authentication error", errors);
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
      throw new Error("User authentication error", errors);
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
    if (this.activeUser.errors && this.activeUser.errros.length > 0) {
      throw new Error("User authentication error", errors);
    };
    if (this.activeUser) {
      const documentReference = this.db.collection(collection).doc(documentId);
      if (data.id) delete data.id;
      await documentReference.update(data);
      return true;
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
    if (this.activeUser.errors && this.activeUser.errros.length > 0) {
      throw new Error("User authentication error", errors);
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
    if (this.activeUser.errors && this.activeUser.errros.length > 0) {
      throw new Error("User authentication error", errors);
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
    const { collection } = args;
    if (this.activeUser.errors && this.activeUser.errros.length > 0) {
      throw new Error("User authentication error", errors);
    };
    if (this.activeUser) {
      try {
        const queryRef = this.db.collection(collection);
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
    const filter = { ...this.defaultFilterOptions, ...filterArgs };
    const page = { ...this.defaultPageOptions, ...pageArgs };
    if (this.activeUser.errors && this.activeUser.errros.length > 0) {
      throw new Error("User authentication error", errors);
    };
    if (this.activeUser) {
      try {
        const queryRef = this.db.collection(collection);
        if (filter.orderBy && filter.orderBy !== "") {
          queryRef = queryRef.orderBy(filter.orderBy, filter.sortOrder);
        };
        if (filter.where && filter.where.length > 0) {
          for (item in filter.where) {
            if (item.field && item.field !== "" && field.value && field.value !== "" && item.condition) {
              queryRef = queryRef.where(item.field, item.condition !== "" ? item.condition : "", item.value);
            }
          }
        };
        if (page.cursor && page.cursor.length > 0) {
          switch (page.direction) {
            case 'forward':
              var forwardCursor = await this.db.collection(collection)
                .doc(page.cursor[page.cursor.length - 1])
                .get();
              queryRef = queryRef
                .startAfter(forwardCursor);
              break;
            case 'back':
              page.cursor = page.cursor.slice(0, page.cursor.length - 2);
              if (page.cursor.length > 0) {
                var backCursor = await this.db.collection(collection)
                  .doc(page.cursor[page.cursor.length - 1])
                  .get();
                queryRef = queryRef
                  .startAfter(backCursor);
              }
              break;
            default:
              break;
          }
        };
        var querySnapshot = await queryRef.limit(page.pageSize).get();
        var documents = [];
        if (querySnapshot.docs.length > 0) {
          page.cursor.push(querySnapshot.docs[querySnapshot.docs.length - 1].id);
          documents = querySnapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
          }));
        };
        if (documents.length === 0 && page.cursor.length) throw new Error("No more paged data.");
        const result = { documents, filter, page };
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

