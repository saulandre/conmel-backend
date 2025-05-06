
/**
 * Client
**/

import * as runtime from './runtime/library.js';
import $Types = runtime.Types // general types
import $Public = runtime.Types.Public
import $Utils = runtime.Types.Utils
import $Extensions = runtime.Types.Extensions
import $Result = runtime.Types.Result

export type PrismaPromise<T> = $Public.PrismaPromise<T>


/**
 * Model Users
 * 
 */
export type Users = $Result.DefaultSelection<Prisma.$UsersPayload>
/**
 * Model InstituicaoEspirita
 * 
 */
export type InstituicaoEspirita = $Result.DefaultSelection<Prisma.$InstituicaoEspiritaPayload>
/**
 * Model Participante2025
 * 
 */
export type Participante2025 = $Result.DefaultSelection<Prisma.$Participante2025Payload>
/**
 * Model PasswordResetToken
 * 
 */
export type PasswordResetToken = $Result.DefaultSelection<Prisma.$PasswordResetTokenPayload>

/**
 * Enums
 */
export namespace $Enums {
  export const Role: {
  user: 'user',
  admin: 'admin'
};

export type Role = (typeof Role)[keyof typeof Role]


export const Sexo: {
  Masculino_CIS: 'Masculino_CIS',
  Feminino_CIS: 'Feminino_CIS',
  Masculino_Trans: 'Masculino_Trans',
  Feminino_Trans: 'Feminino_Trans',
  Nao_binario: 'Nao_binario'
};

export type Sexo = (typeof Sexo)[keyof typeof Sexo]


export const TipoParticipacao: {
  Confraternista: 'Confraternista',
  Trabalhador: 'Trabalhador'
};

export type TipoParticipacao = (typeof TipoParticipacao)[keyof typeof TipoParticipacao]

}

export type Role = $Enums.Role

export const Role: typeof $Enums.Role

export type Sexo = $Enums.Sexo

export const Sexo: typeof $Enums.Sexo

export type TipoParticipacao = $Enums.TipoParticipacao

export const TipoParticipacao: typeof $Enums.TipoParticipacao

/**
 * ##  Prisma Client ʲˢ
 *
 * Type-safe database client for TypeScript & Node.js
 * @example
 * ```
 * const prisma = new PrismaClient()
 * // Fetch zero or more Users
 * const users = await prisma.users.findMany()
 * ```
 *
 *
 * Read more in our [docs](https://www.prisma.io/docs/reference/tools-and-interfaces/prisma-client).
 */
export class PrismaClient<
  ClientOptions extends Prisma.PrismaClientOptions = Prisma.PrismaClientOptions,
  U = 'log' extends keyof ClientOptions ? ClientOptions['log'] extends Array<Prisma.LogLevel | Prisma.LogDefinition> ? Prisma.GetEvents<ClientOptions['log']> : never : never,
  ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs
> {
  [K: symbol]: { types: Prisma.TypeMap<ExtArgs>['other'] }

    /**
   * ##  Prisma Client ʲˢ
   *
   * Type-safe database client for TypeScript & Node.js
   * @example
   * ```
   * const prisma = new PrismaClient()
   * // Fetch zero or more Users
   * const users = await prisma.users.findMany()
   * ```
   *
   *
   * Read more in our [docs](https://www.prisma.io/docs/reference/tools-and-interfaces/prisma-client).
   */

  constructor(optionsArg ?: Prisma.Subset<ClientOptions, Prisma.PrismaClientOptions>);
  $on<V extends U>(eventType: V, callback: (event: V extends 'query' ? Prisma.QueryEvent : Prisma.LogEvent) => void): PrismaClient;

  /**
   * Connect with the database
   */
  $connect(): $Utils.JsPromise<void>;

  /**
   * Disconnect from the database
   */
  $disconnect(): $Utils.JsPromise<void>;

  /**
   * Add a middleware
   * @deprecated since 4.16.0. For new code, prefer client extensions instead.
   * @see https://pris.ly/d/extensions
   */
  $use(cb: Prisma.Middleware): void

/**
   * Executes a prepared raw query and returns the number of affected rows.
   * @example
   * ```
   * const result = await prisma.$executeRaw`UPDATE User SET cool = ${true} WHERE email = ${'user@email.com'};`
   * ```
   *
   * Read more in our [docs](https://www.prisma.io/docs/reference/tools-and-interfaces/prisma-client/raw-database-access).
   */
  $executeRaw<T = unknown>(query: TemplateStringsArray | Prisma.Sql, ...values: any[]): Prisma.PrismaPromise<number>;

  /**
   * Executes a raw query and returns the number of affected rows.
   * Susceptible to SQL injections, see documentation.
   * @example
   * ```
   * const result = await prisma.$executeRawUnsafe('UPDATE User SET cool = $1 WHERE email = $2 ;', true, 'user@email.com')
   * ```
   *
   * Read more in our [docs](https://www.prisma.io/docs/reference/tools-and-interfaces/prisma-client/raw-database-access).
   */
  $executeRawUnsafe<T = unknown>(query: string, ...values: any[]): Prisma.PrismaPromise<number>;

  /**
   * Performs a prepared raw query and returns the `SELECT` data.
   * @example
   * ```
   * const result = await prisma.$queryRaw`SELECT * FROM User WHERE id = ${1} OR email = ${'user@email.com'};`
   * ```
   *
   * Read more in our [docs](https://www.prisma.io/docs/reference/tools-and-interfaces/prisma-client/raw-database-access).
   */
  $queryRaw<T = unknown>(query: TemplateStringsArray | Prisma.Sql, ...values: any[]): Prisma.PrismaPromise<T>;

  /**
   * Performs a raw query and returns the `SELECT` data.
   * Susceptible to SQL injections, see documentation.
   * @example
   * ```
   * const result = await prisma.$queryRawUnsafe('SELECT * FROM User WHERE id = $1 OR email = $2;', 1, 'user@email.com')
   * ```
   *
   * Read more in our [docs](https://www.prisma.io/docs/reference/tools-and-interfaces/prisma-client/raw-database-access).
   */
  $queryRawUnsafe<T = unknown>(query: string, ...values: any[]): Prisma.PrismaPromise<T>;


  /**
   * Allows the running of a sequence of read/write operations that are guaranteed to either succeed or fail as a whole.
   * @example
   * ```
   * const [george, bob, alice] = await prisma.$transaction([
   *   prisma.user.create({ data: { name: 'George' } }),
   *   prisma.user.create({ data: { name: 'Bob' } }),
   *   prisma.user.create({ data: { name: 'Alice' } }),
   * ])
   * ```
   * 
   * Read more in our [docs](https://www.prisma.io/docs/concepts/components/prisma-client/transactions).
   */
  $transaction<P extends Prisma.PrismaPromise<any>[]>(arg: [...P], options?: { isolationLevel?: Prisma.TransactionIsolationLevel }): $Utils.JsPromise<runtime.Types.Utils.UnwrapTuple<P>>

  $transaction<R>(fn: (prisma: Omit<PrismaClient, runtime.ITXClientDenyList>) => $Utils.JsPromise<R>, options?: { maxWait?: number, timeout?: number, isolationLevel?: Prisma.TransactionIsolationLevel }): $Utils.JsPromise<R>


  $extends: $Extensions.ExtendsHook<"extends", Prisma.TypeMapCb<ClientOptions>, ExtArgs, $Utils.Call<Prisma.TypeMapCb<ClientOptions>, {
    extArgs: ExtArgs
  }>>

      /**
   * `prisma.users`: Exposes CRUD operations for the **Users** model.
    * Example usage:
    * ```ts
    * // Fetch zero or more Users
    * const users = await prisma.users.findMany()
    * ```
    */
  get users(): Prisma.UsersDelegate<ExtArgs, ClientOptions>;

  /**
   * `prisma.instituicaoEspirita`: Exposes CRUD operations for the **InstituicaoEspirita** model.
    * Example usage:
    * ```ts
    * // Fetch zero or more InstituicaoEspiritas
    * const instituicaoEspiritas = await prisma.instituicaoEspirita.findMany()
    * ```
    */
  get instituicaoEspirita(): Prisma.InstituicaoEspiritaDelegate<ExtArgs, ClientOptions>;

  /**
   * `prisma.participante2025`: Exposes CRUD operations for the **Participante2025** model.
    * Example usage:
    * ```ts
    * // Fetch zero or more Participante2025s
    * const participante2025s = await prisma.participante2025.findMany()
    * ```
    */
  get participante2025(): Prisma.Participante2025Delegate<ExtArgs, ClientOptions>;

  /**
   * `prisma.passwordResetToken`: Exposes CRUD operations for the **PasswordResetToken** model.
    * Example usage:
    * ```ts
    * // Fetch zero or more PasswordResetTokens
    * const passwordResetTokens = await prisma.passwordResetToken.findMany()
    * ```
    */
  get passwordResetToken(): Prisma.PasswordResetTokenDelegate<ExtArgs, ClientOptions>;
}

export namespace Prisma {
  export import DMMF = runtime.DMMF

  export type PrismaPromise<T> = $Public.PrismaPromise<T>

  /**
   * Validator
   */
  export import validator = runtime.Public.validator

  /**
   * Prisma Errors
   */
  export import PrismaClientKnownRequestError = runtime.PrismaClientKnownRequestError
  export import PrismaClientUnknownRequestError = runtime.PrismaClientUnknownRequestError
  export import PrismaClientRustPanicError = runtime.PrismaClientRustPanicError
  export import PrismaClientInitializationError = runtime.PrismaClientInitializationError
  export import PrismaClientValidationError = runtime.PrismaClientValidationError

  /**
   * Re-export of sql-template-tag
   */
  export import sql = runtime.sqltag
  export import empty = runtime.empty
  export import join = runtime.join
  export import raw = runtime.raw
  export import Sql = runtime.Sql



  /**
   * Decimal.js
   */
  export import Decimal = runtime.Decimal

  export type DecimalJsLike = runtime.DecimalJsLike

  /**
   * Metrics
   */
  export type Metrics = runtime.Metrics
  export type Metric<T> = runtime.Metric<T>
  export type MetricHistogram = runtime.MetricHistogram
  export type MetricHistogramBucket = runtime.MetricHistogramBucket

  /**
  * Extensions
  */
  export import Extension = $Extensions.UserArgs
  export import getExtensionContext = runtime.Extensions.getExtensionContext
  export import Args = $Public.Args
  export import Payload = $Public.Payload
  export import Result = $Public.Result
  export import Exact = $Public.Exact

  /**
   * Prisma Client JS version: 6.7.0
   * Query Engine version: 3cff47a7f5d65c3ea74883f1d736e41d68ce91ed
   */
  export type PrismaVersion = {
    client: string
  }

  export const prismaVersion: PrismaVersion

  /**
   * Utility Types
   */


  export import JsonObject = runtime.JsonObject
  export import JsonArray = runtime.JsonArray
  export import JsonValue = runtime.JsonValue
  export import InputJsonObject = runtime.InputJsonObject
  export import InputJsonArray = runtime.InputJsonArray
  export import InputJsonValue = runtime.InputJsonValue

  /**
   * Types of the values used to represent different kinds of `null` values when working with JSON fields.
   *
   * @see https://www.prisma.io/docs/concepts/components/prisma-client/working-with-fields/working-with-json-fields#filtering-on-a-json-field
   */
  namespace NullTypes {
    /**
    * Type of `Prisma.DbNull`.
    *
    * You cannot use other instances of this class. Please use the `Prisma.DbNull` value.
    *
    * @see https://www.prisma.io/docs/concepts/components/prisma-client/working-with-fields/working-with-json-fields#filtering-on-a-json-field
    */
    class DbNull {
      private DbNull: never
      private constructor()
    }

    /**
    * Type of `Prisma.JsonNull`.
    *
    * You cannot use other instances of this class. Please use the `Prisma.JsonNull` value.
    *
    * @see https://www.prisma.io/docs/concepts/components/prisma-client/working-with-fields/working-with-json-fields#filtering-on-a-json-field
    */
    class JsonNull {
      private JsonNull: never
      private constructor()
    }

    /**
    * Type of `Prisma.AnyNull`.
    *
    * You cannot use other instances of this class. Please use the `Prisma.AnyNull` value.
    *
    * @see https://www.prisma.io/docs/concepts/components/prisma-client/working-with-fields/working-with-json-fields#filtering-on-a-json-field
    */
    class AnyNull {
      private AnyNull: never
      private constructor()
    }
  }

  /**
   * Helper for filtering JSON entries that have `null` on the database (empty on the db)
   *
   * @see https://www.prisma.io/docs/concepts/components/prisma-client/working-with-fields/working-with-json-fields#filtering-on-a-json-field
   */
  export const DbNull: NullTypes.DbNull

  /**
   * Helper for filtering JSON entries that have JSON `null` values (not empty on the db)
   *
   * @see https://www.prisma.io/docs/concepts/components/prisma-client/working-with-fields/working-with-json-fields#filtering-on-a-json-field
   */
  export const JsonNull: NullTypes.JsonNull

  /**
   * Helper for filtering JSON entries that are `Prisma.DbNull` or `Prisma.JsonNull`
   *
   * @see https://www.prisma.io/docs/concepts/components/prisma-client/working-with-fields/working-with-json-fields#filtering-on-a-json-field
   */
  export const AnyNull: NullTypes.AnyNull

  type SelectAndInclude = {
    select: any
    include: any
  }

  type SelectAndOmit = {
    select: any
    omit: any
  }

  /**
   * Get the type of the value, that the Promise holds.
   */
  export type PromiseType<T extends PromiseLike<any>> = T extends PromiseLike<infer U> ? U : T;

  /**
   * Get the return type of a function which returns a Promise.
   */
  export type PromiseReturnType<T extends (...args: any) => $Utils.JsPromise<any>> = PromiseType<ReturnType<T>>

  /**
   * From T, pick a set of properties whose keys are in the union K
   */
  type Prisma__Pick<T, K extends keyof T> = {
      [P in K]: T[P];
  };


  export type Enumerable<T> = T | Array<T>;

  export type RequiredKeys<T> = {
    [K in keyof T]-?: {} extends Prisma__Pick<T, K> ? never : K
  }[keyof T]

  export type TruthyKeys<T> = keyof {
    [K in keyof T as T[K] extends false | undefined | null ? never : K]: K
  }

  export type TrueKeys<T> = TruthyKeys<Prisma__Pick<T, RequiredKeys<T>>>

  /**
   * Subset
   * @desc From `T` pick properties that exist in `U`. Simple version of Intersection
   */
  export type Subset<T, U> = {
    [key in keyof T]: key extends keyof U ? T[key] : never;
  };

  /**
   * SelectSubset
   * @desc From `T` pick properties that exist in `U`. Simple version of Intersection.
   * Additionally, it validates, if both select and include are present. If the case, it errors.
   */
  export type SelectSubset<T, U> = {
    [key in keyof T]: key extends keyof U ? T[key] : never
  } &
    (T extends SelectAndInclude
      ? 'Please either choose `select` or `include`.'
      : T extends SelectAndOmit
        ? 'Please either choose `select` or `omit`.'
        : {})

  /**
   * Subset + Intersection
   * @desc From `T` pick properties that exist in `U` and intersect `K`
   */
  export type SubsetIntersection<T, U, K> = {
    [key in keyof T]: key extends keyof U ? T[key] : never
  } &
    K

  type Without<T, U> = { [P in Exclude<keyof T, keyof U>]?: never };

  /**
   * XOR is needed to have a real mutually exclusive union type
   * https://stackoverflow.com/questions/42123407/does-typescript-support-mutually-exclusive-types
   */
  type XOR<T, U> =
    T extends object ?
    U extends object ?
      (Without<T, U> & U) | (Without<U, T> & T)
    : U : T


  /**
   * Is T a Record?
   */
  type IsObject<T extends any> = T extends Array<any>
  ? False
  : T extends Date
  ? False
  : T extends Uint8Array
  ? False
  : T extends BigInt
  ? False
  : T extends object
  ? True
  : False


  /**
   * If it's T[], return T
   */
  export type UnEnumerate<T extends unknown> = T extends Array<infer U> ? U : T

  /**
   * From ts-toolbelt
   */

  type __Either<O extends object, K extends Key> = Omit<O, K> &
    {
      // Merge all but K
      [P in K]: Prisma__Pick<O, P & keyof O> // With K possibilities
    }[K]

  type EitherStrict<O extends object, K extends Key> = Strict<__Either<O, K>>

  type EitherLoose<O extends object, K extends Key> = ComputeRaw<__Either<O, K>>

  type _Either<
    O extends object,
    K extends Key,
    strict extends Boolean
  > = {
    1: EitherStrict<O, K>
    0: EitherLoose<O, K>
  }[strict]

  type Either<
    O extends object,
    K extends Key,
    strict extends Boolean = 1
  > = O extends unknown ? _Either<O, K, strict> : never

  export type Union = any

  type PatchUndefined<O extends object, O1 extends object> = {
    [K in keyof O]: O[K] extends undefined ? At<O1, K> : O[K]
  } & {}

  /** Helper Types for "Merge" **/
  export type IntersectOf<U extends Union> = (
    U extends unknown ? (k: U) => void : never
  ) extends (k: infer I) => void
    ? I
    : never

  export type Overwrite<O extends object, O1 extends object> = {
      [K in keyof O]: K extends keyof O1 ? O1[K] : O[K];
  } & {};

  type _Merge<U extends object> = IntersectOf<Overwrite<U, {
      [K in keyof U]-?: At<U, K>;
  }>>;

  type Key = string | number | symbol;
  type AtBasic<O extends object, K extends Key> = K extends keyof O ? O[K] : never;
  type AtStrict<O extends object, K extends Key> = O[K & keyof O];
  type AtLoose<O extends object, K extends Key> = O extends unknown ? AtStrict<O, K> : never;
  export type At<O extends object, K extends Key, strict extends Boolean = 1> = {
      1: AtStrict<O, K>;
      0: AtLoose<O, K>;
  }[strict];

  export type ComputeRaw<A extends any> = A extends Function ? A : {
    [K in keyof A]: A[K];
  } & {};

  export type OptionalFlat<O> = {
    [K in keyof O]?: O[K];
  } & {};

  type _Record<K extends keyof any, T> = {
    [P in K]: T;
  };

  // cause typescript not to expand types and preserve names
  type NoExpand<T> = T extends unknown ? T : never;

  // this type assumes the passed object is entirely optional
  type AtLeast<O extends object, K extends string> = NoExpand<
    O extends unknown
    ? | (K extends keyof O ? { [P in K]: O[P] } & O : O)
      | {[P in keyof O as P extends K ? P : never]-?: O[P]} & O
    : never>;

  type _Strict<U, _U = U> = U extends unknown ? U & OptionalFlat<_Record<Exclude<Keys<_U>, keyof U>, never>> : never;

  export type Strict<U extends object> = ComputeRaw<_Strict<U>>;
  /** End Helper Types for "Merge" **/

  export type Merge<U extends object> = ComputeRaw<_Merge<Strict<U>>>;

  /**
  A [[Boolean]]
  */
  export type Boolean = True | False

  // /**
  // 1
  // */
  export type True = 1

  /**
  0
  */
  export type False = 0

  export type Not<B extends Boolean> = {
    0: 1
    1: 0
  }[B]

  export type Extends<A1 extends any, A2 extends any> = [A1] extends [never]
    ? 0 // anything `never` is false
    : A1 extends A2
    ? 1
    : 0

  export type Has<U extends Union, U1 extends Union> = Not<
    Extends<Exclude<U1, U>, U1>
  >

  export type Or<B1 extends Boolean, B2 extends Boolean> = {
    0: {
      0: 0
      1: 1
    }
    1: {
      0: 1
      1: 1
    }
  }[B1][B2]

  export type Keys<U extends Union> = U extends unknown ? keyof U : never

  type Cast<A, B> = A extends B ? A : B;

  export const type: unique symbol;



  /**
   * Used by group by
   */

  export type GetScalarType<T, O> = O extends object ? {
    [P in keyof T]: P extends keyof O
      ? O[P]
      : never
  } : never

  type FieldPaths<
    T,
    U = Omit<T, '_avg' | '_sum' | '_count' | '_min' | '_max'>
  > = IsObject<T> extends True ? U : T

  type GetHavingFields<T> = {
    [K in keyof T]: Or<
      Or<Extends<'OR', K>, Extends<'AND', K>>,
      Extends<'NOT', K>
    > extends True
      ? // infer is only needed to not hit TS limit
        // based on the brilliant idea of Pierre-Antoine Mills
        // https://github.com/microsoft/TypeScript/issues/30188#issuecomment-478938437
        T[K] extends infer TK
        ? GetHavingFields<UnEnumerate<TK> extends object ? Merge<UnEnumerate<TK>> : never>
        : never
      : {} extends FieldPaths<T[K]>
      ? never
      : K
  }[keyof T]

  /**
   * Convert tuple to union
   */
  type _TupleToUnion<T> = T extends (infer E)[] ? E : never
  type TupleToUnion<K extends readonly any[]> = _TupleToUnion<K>
  type MaybeTupleToUnion<T> = T extends any[] ? TupleToUnion<T> : T

  /**
   * Like `Pick`, but additionally can also accept an array of keys
   */
  type PickEnumerable<T, K extends Enumerable<keyof T> | keyof T> = Prisma__Pick<T, MaybeTupleToUnion<K>>

  /**
   * Exclude all keys with underscores
   */
  type ExcludeUnderscoreKeys<T extends string> = T extends `_${string}` ? never : T


  export type FieldRef<Model, FieldType> = runtime.FieldRef<Model, FieldType>

  type FieldRefInputType<Model, FieldType> = Model extends never ? never : FieldRef<Model, FieldType>


  export const ModelName: {
    Users: 'Users',
    InstituicaoEspirita: 'InstituicaoEspirita',
    Participante2025: 'Participante2025',
    PasswordResetToken: 'PasswordResetToken'
  };

  export type ModelName = (typeof ModelName)[keyof typeof ModelName]


  export type Datasources = {
    db?: Datasource
  }

  interface TypeMapCb<ClientOptions = {}> extends $Utils.Fn<{extArgs: $Extensions.InternalArgs }, $Utils.Record<string, any>> {
    returns: Prisma.TypeMap<this['params']['extArgs'], ClientOptions extends { omit: infer OmitOptions } ? OmitOptions : {}>
  }

  export type TypeMap<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs, GlobalOmitOptions = {}> = {
    globalOmitOptions: {
      omit: GlobalOmitOptions
    }
    meta: {
      modelProps: "users" | "instituicaoEspirita" | "participante2025" | "passwordResetToken"
      txIsolationLevel: Prisma.TransactionIsolationLevel
    }
    model: {
      Users: {
        payload: Prisma.$UsersPayload<ExtArgs>
        fields: Prisma.UsersFieldRefs
        operations: {
          findUnique: {
            args: Prisma.UsersFindUniqueArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$UsersPayload> | null
          }
          findUniqueOrThrow: {
            args: Prisma.UsersFindUniqueOrThrowArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$UsersPayload>
          }
          findFirst: {
            args: Prisma.UsersFindFirstArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$UsersPayload> | null
          }
          findFirstOrThrow: {
            args: Prisma.UsersFindFirstOrThrowArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$UsersPayload>
          }
          findMany: {
            args: Prisma.UsersFindManyArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$UsersPayload>[]
          }
          create: {
            args: Prisma.UsersCreateArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$UsersPayload>
          }
          createMany: {
            args: Prisma.UsersCreateManyArgs<ExtArgs>
            result: BatchPayload
          }
          createManyAndReturn: {
            args: Prisma.UsersCreateManyAndReturnArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$UsersPayload>[]
          }
          delete: {
            args: Prisma.UsersDeleteArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$UsersPayload>
          }
          update: {
            args: Prisma.UsersUpdateArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$UsersPayload>
          }
          deleteMany: {
            args: Prisma.UsersDeleteManyArgs<ExtArgs>
            result: BatchPayload
          }
          updateMany: {
            args: Prisma.UsersUpdateManyArgs<ExtArgs>
            result: BatchPayload
          }
          updateManyAndReturn: {
            args: Prisma.UsersUpdateManyAndReturnArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$UsersPayload>[]
          }
          upsert: {
            args: Prisma.UsersUpsertArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$UsersPayload>
          }
          aggregate: {
            args: Prisma.UsersAggregateArgs<ExtArgs>
            result: $Utils.Optional<AggregateUsers>
          }
          groupBy: {
            args: Prisma.UsersGroupByArgs<ExtArgs>
            result: $Utils.Optional<UsersGroupByOutputType>[]
          }
          count: {
            args: Prisma.UsersCountArgs<ExtArgs>
            result: $Utils.Optional<UsersCountAggregateOutputType> | number
          }
        }
      }
      InstituicaoEspirita: {
        payload: Prisma.$InstituicaoEspiritaPayload<ExtArgs>
        fields: Prisma.InstituicaoEspiritaFieldRefs
        operations: {
          findUnique: {
            args: Prisma.InstituicaoEspiritaFindUniqueArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$InstituicaoEspiritaPayload> | null
          }
          findUniqueOrThrow: {
            args: Prisma.InstituicaoEspiritaFindUniqueOrThrowArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$InstituicaoEspiritaPayload>
          }
          findFirst: {
            args: Prisma.InstituicaoEspiritaFindFirstArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$InstituicaoEspiritaPayload> | null
          }
          findFirstOrThrow: {
            args: Prisma.InstituicaoEspiritaFindFirstOrThrowArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$InstituicaoEspiritaPayload>
          }
          findMany: {
            args: Prisma.InstituicaoEspiritaFindManyArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$InstituicaoEspiritaPayload>[]
          }
          create: {
            args: Prisma.InstituicaoEspiritaCreateArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$InstituicaoEspiritaPayload>
          }
          createMany: {
            args: Prisma.InstituicaoEspiritaCreateManyArgs<ExtArgs>
            result: BatchPayload
          }
          createManyAndReturn: {
            args: Prisma.InstituicaoEspiritaCreateManyAndReturnArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$InstituicaoEspiritaPayload>[]
          }
          delete: {
            args: Prisma.InstituicaoEspiritaDeleteArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$InstituicaoEspiritaPayload>
          }
          update: {
            args: Prisma.InstituicaoEspiritaUpdateArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$InstituicaoEspiritaPayload>
          }
          deleteMany: {
            args: Prisma.InstituicaoEspiritaDeleteManyArgs<ExtArgs>
            result: BatchPayload
          }
          updateMany: {
            args: Prisma.InstituicaoEspiritaUpdateManyArgs<ExtArgs>
            result: BatchPayload
          }
          updateManyAndReturn: {
            args: Prisma.InstituicaoEspiritaUpdateManyAndReturnArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$InstituicaoEspiritaPayload>[]
          }
          upsert: {
            args: Prisma.InstituicaoEspiritaUpsertArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$InstituicaoEspiritaPayload>
          }
          aggregate: {
            args: Prisma.InstituicaoEspiritaAggregateArgs<ExtArgs>
            result: $Utils.Optional<AggregateInstituicaoEspirita>
          }
          groupBy: {
            args: Prisma.InstituicaoEspiritaGroupByArgs<ExtArgs>
            result: $Utils.Optional<InstituicaoEspiritaGroupByOutputType>[]
          }
          count: {
            args: Prisma.InstituicaoEspiritaCountArgs<ExtArgs>
            result: $Utils.Optional<InstituicaoEspiritaCountAggregateOutputType> | number
          }
        }
      }
      Participante2025: {
        payload: Prisma.$Participante2025Payload<ExtArgs>
        fields: Prisma.Participante2025FieldRefs
        operations: {
          findUnique: {
            args: Prisma.Participante2025FindUniqueArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$Participante2025Payload> | null
          }
          findUniqueOrThrow: {
            args: Prisma.Participante2025FindUniqueOrThrowArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$Participante2025Payload>
          }
          findFirst: {
            args: Prisma.Participante2025FindFirstArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$Participante2025Payload> | null
          }
          findFirstOrThrow: {
            args: Prisma.Participante2025FindFirstOrThrowArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$Participante2025Payload>
          }
          findMany: {
            args: Prisma.Participante2025FindManyArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$Participante2025Payload>[]
          }
          create: {
            args: Prisma.Participante2025CreateArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$Participante2025Payload>
          }
          createMany: {
            args: Prisma.Participante2025CreateManyArgs<ExtArgs>
            result: BatchPayload
          }
          createManyAndReturn: {
            args: Prisma.Participante2025CreateManyAndReturnArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$Participante2025Payload>[]
          }
          delete: {
            args: Prisma.Participante2025DeleteArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$Participante2025Payload>
          }
          update: {
            args: Prisma.Participante2025UpdateArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$Participante2025Payload>
          }
          deleteMany: {
            args: Prisma.Participante2025DeleteManyArgs<ExtArgs>
            result: BatchPayload
          }
          updateMany: {
            args: Prisma.Participante2025UpdateManyArgs<ExtArgs>
            result: BatchPayload
          }
          updateManyAndReturn: {
            args: Prisma.Participante2025UpdateManyAndReturnArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$Participante2025Payload>[]
          }
          upsert: {
            args: Prisma.Participante2025UpsertArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$Participante2025Payload>
          }
          aggregate: {
            args: Prisma.Participante2025AggregateArgs<ExtArgs>
            result: $Utils.Optional<AggregateParticipante2025>
          }
          groupBy: {
            args: Prisma.Participante2025GroupByArgs<ExtArgs>
            result: $Utils.Optional<Participante2025GroupByOutputType>[]
          }
          count: {
            args: Prisma.Participante2025CountArgs<ExtArgs>
            result: $Utils.Optional<Participante2025CountAggregateOutputType> | number
          }
        }
      }
      PasswordResetToken: {
        payload: Prisma.$PasswordResetTokenPayload<ExtArgs>
        fields: Prisma.PasswordResetTokenFieldRefs
        operations: {
          findUnique: {
            args: Prisma.PasswordResetTokenFindUniqueArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$PasswordResetTokenPayload> | null
          }
          findUniqueOrThrow: {
            args: Prisma.PasswordResetTokenFindUniqueOrThrowArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$PasswordResetTokenPayload>
          }
          findFirst: {
            args: Prisma.PasswordResetTokenFindFirstArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$PasswordResetTokenPayload> | null
          }
          findFirstOrThrow: {
            args: Prisma.PasswordResetTokenFindFirstOrThrowArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$PasswordResetTokenPayload>
          }
          findMany: {
            args: Prisma.PasswordResetTokenFindManyArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$PasswordResetTokenPayload>[]
          }
          create: {
            args: Prisma.PasswordResetTokenCreateArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$PasswordResetTokenPayload>
          }
          createMany: {
            args: Prisma.PasswordResetTokenCreateManyArgs<ExtArgs>
            result: BatchPayload
          }
          createManyAndReturn: {
            args: Prisma.PasswordResetTokenCreateManyAndReturnArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$PasswordResetTokenPayload>[]
          }
          delete: {
            args: Prisma.PasswordResetTokenDeleteArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$PasswordResetTokenPayload>
          }
          update: {
            args: Prisma.PasswordResetTokenUpdateArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$PasswordResetTokenPayload>
          }
          deleteMany: {
            args: Prisma.PasswordResetTokenDeleteManyArgs<ExtArgs>
            result: BatchPayload
          }
          updateMany: {
            args: Prisma.PasswordResetTokenUpdateManyArgs<ExtArgs>
            result: BatchPayload
          }
          updateManyAndReturn: {
            args: Prisma.PasswordResetTokenUpdateManyAndReturnArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$PasswordResetTokenPayload>[]
          }
          upsert: {
            args: Prisma.PasswordResetTokenUpsertArgs<ExtArgs>
            result: $Utils.PayloadToResult<Prisma.$PasswordResetTokenPayload>
          }
          aggregate: {
            args: Prisma.PasswordResetTokenAggregateArgs<ExtArgs>
            result: $Utils.Optional<AggregatePasswordResetToken>
          }
          groupBy: {
            args: Prisma.PasswordResetTokenGroupByArgs<ExtArgs>
            result: $Utils.Optional<PasswordResetTokenGroupByOutputType>[]
          }
          count: {
            args: Prisma.PasswordResetTokenCountArgs<ExtArgs>
            result: $Utils.Optional<PasswordResetTokenCountAggregateOutputType> | number
          }
        }
      }
    }
  } & {
    other: {
      payload: any
      operations: {
        $executeRaw: {
          args: [query: TemplateStringsArray | Prisma.Sql, ...values: any[]],
          result: any
        }
        $executeRawUnsafe: {
          args: [query: string, ...values: any[]],
          result: any
        }
        $queryRaw: {
          args: [query: TemplateStringsArray | Prisma.Sql, ...values: any[]],
          result: any
        }
        $queryRawUnsafe: {
          args: [query: string, ...values: any[]],
          result: any
        }
      }
    }
  }
  export const defineExtension: $Extensions.ExtendsHook<"define", Prisma.TypeMapCb, $Extensions.DefaultArgs>
  export type DefaultPrismaClient = PrismaClient
  export type ErrorFormat = 'pretty' | 'colorless' | 'minimal'
  export interface PrismaClientOptions {
    /**
     * Overwrites the datasource url from your schema.prisma file
     */
    datasources?: Datasources
    /**
     * Overwrites the datasource url from your schema.prisma file
     */
    datasourceUrl?: string
    /**
     * @default "colorless"
     */
    errorFormat?: ErrorFormat
    /**
     * @example
     * ```
     * // Defaults to stdout
     * log: ['query', 'info', 'warn', 'error']
     * 
     * // Emit as events
     * log: [
     *   { emit: 'stdout', level: 'query' },
     *   { emit: 'stdout', level: 'info' },
     *   { emit: 'stdout', level: 'warn' }
     *   { emit: 'stdout', level: 'error' }
     * ]
     * ```
     * Read more in our [docs](https://www.prisma.io/docs/reference/tools-and-interfaces/prisma-client/logging#the-log-option).
     */
    log?: (LogLevel | LogDefinition)[]
    /**
     * The default values for transactionOptions
     * maxWait ?= 2000
     * timeout ?= 5000
     */
    transactionOptions?: {
      maxWait?: number
      timeout?: number
      isolationLevel?: Prisma.TransactionIsolationLevel
    }
    /**
     * Global configuration for omitting model fields by default.
     * 
     * @example
     * ```
     * const prisma = new PrismaClient({
     *   omit: {
     *     user: {
     *       password: true
     *     }
     *   }
     * })
     * ```
     */
    omit?: Prisma.GlobalOmitConfig
  }
  export type GlobalOmitConfig = {
    users?: UsersOmit
    instituicaoEspirita?: InstituicaoEspiritaOmit
    participante2025?: Participante2025Omit
    passwordResetToken?: PasswordResetTokenOmit
  }

  /* Types for Logging */
  export type LogLevel = 'info' | 'query' | 'warn' | 'error'
  export type LogDefinition = {
    level: LogLevel
    emit: 'stdout' | 'event'
  }

  export type GetLogType<T extends LogLevel | LogDefinition> = T extends LogDefinition ? T['emit'] extends 'event' ? T['level'] : never : never
  export type GetEvents<T extends any> = T extends Array<LogLevel | LogDefinition> ?
    GetLogType<T[0]> | GetLogType<T[1]> | GetLogType<T[2]> | GetLogType<T[3]>
    : never

  export type QueryEvent = {
    timestamp: Date
    query: string
    params: string
    duration: number
    target: string
  }

  export type LogEvent = {
    timestamp: Date
    message: string
    target: string
  }
  /* End Types for Logging */


  export type PrismaAction =
    | 'findUnique'
    | 'findUniqueOrThrow'
    | 'findMany'
    | 'findFirst'
    | 'findFirstOrThrow'
    | 'create'
    | 'createMany'
    | 'createManyAndReturn'
    | 'update'
    | 'updateMany'
    | 'updateManyAndReturn'
    | 'upsert'
    | 'delete'
    | 'deleteMany'
    | 'executeRaw'
    | 'queryRaw'
    | 'aggregate'
    | 'count'
    | 'runCommandRaw'
    | 'findRaw'
    | 'groupBy'

  /**
   * These options are being passed into the middleware as "params"
   */
  export type MiddlewareParams = {
    model?: ModelName
    action: PrismaAction
    args: any
    dataPath: string[]
    runInTransaction: boolean
  }

  /**
   * The `T` type makes sure, that the `return proceed` is not forgotten in the middleware implementation
   */
  export type Middleware<T = any> = (
    params: MiddlewareParams,
    next: (params: MiddlewareParams) => $Utils.JsPromise<T>,
  ) => $Utils.JsPromise<T>

  // tested in getLogLevel.test.ts
  export function getLogLevel(log: Array<LogLevel | LogDefinition>): LogLevel | undefined;

  /**
   * `PrismaClient` proxy available in interactive transactions.
   */
  export type TransactionClient = Omit<Prisma.DefaultPrismaClient, runtime.ITXClientDenyList>

  export type Datasource = {
    url?: string
  }

  /**
   * Count Types
   */


  /**
   * Count Type UsersCountOutputType
   */

  export type UsersCountOutputType = {
    instituicoesAtualizadas: number
    instituicoesCriadas: number
    Participante2025: number
    instituicoes: number
    passwordResetTokens: number
  }

  export type UsersCountOutputTypeSelect<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    instituicoesAtualizadas?: boolean | UsersCountOutputTypeCountInstituicoesAtualizadasArgs
    instituicoesCriadas?: boolean | UsersCountOutputTypeCountInstituicoesCriadasArgs
    Participante2025?: boolean | UsersCountOutputTypeCountParticipante2025Args
    instituicoes?: boolean | UsersCountOutputTypeCountInstituicoesArgs
    passwordResetTokens?: boolean | UsersCountOutputTypeCountPasswordResetTokensArgs
  }

  // Custom InputTypes
  /**
   * UsersCountOutputType without action
   */
  export type UsersCountOutputTypeDefaultArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the UsersCountOutputType
     */
    select?: UsersCountOutputTypeSelect<ExtArgs> | null
  }

  /**
   * UsersCountOutputType without action
   */
  export type UsersCountOutputTypeCountInstituicoesAtualizadasArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    where?: InstituicaoEspiritaWhereInput
  }

  /**
   * UsersCountOutputType without action
   */
  export type UsersCountOutputTypeCountInstituicoesCriadasArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    where?: InstituicaoEspiritaWhereInput
  }

  /**
   * UsersCountOutputType without action
   */
  export type UsersCountOutputTypeCountParticipante2025Args<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    where?: Participante2025WhereInput
  }

  /**
   * UsersCountOutputType without action
   */
  export type UsersCountOutputTypeCountInstituicoesArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    where?: InstituicaoEspiritaWhereInput
  }

  /**
   * UsersCountOutputType without action
   */
  export type UsersCountOutputTypeCountPasswordResetTokensArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    where?: PasswordResetTokenWhereInput
  }


  /**
   * Count Type InstituicaoEspiritaCountOutputType
   */

  export type InstituicaoEspiritaCountOutputType = {
    Participante2025: number
    Users: number
  }

  export type InstituicaoEspiritaCountOutputTypeSelect<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    Participante2025?: boolean | InstituicaoEspiritaCountOutputTypeCountParticipante2025Args
    Users?: boolean | InstituicaoEspiritaCountOutputTypeCountUsersArgs
  }

  // Custom InputTypes
  /**
   * InstituicaoEspiritaCountOutputType without action
   */
  export type InstituicaoEspiritaCountOutputTypeDefaultArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the InstituicaoEspiritaCountOutputType
     */
    select?: InstituicaoEspiritaCountOutputTypeSelect<ExtArgs> | null
  }

  /**
   * InstituicaoEspiritaCountOutputType without action
   */
  export type InstituicaoEspiritaCountOutputTypeCountParticipante2025Args<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    where?: Participante2025WhereInput
  }

  /**
   * InstituicaoEspiritaCountOutputType without action
   */
  export type InstituicaoEspiritaCountOutputTypeCountUsersArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    where?: UsersWhereInput
  }


  /**
   * Models
   */

  /**
   * Model Users
   */

  export type AggregateUsers = {
    _count: UsersCountAggregateOutputType | null
    _avg: UsersAvgAggregateOutputType | null
    _sum: UsersSumAggregateOutputType | null
    _min: UsersMinAggregateOutputType | null
    _max: UsersMaxAggregateOutputType | null
  }

  export type UsersAvgAggregateOutputType = {
    id: number | null
    resetTokenVersion: number | null
  }

  export type UsersSumAggregateOutputType = {
    id: number | null
    resetTokenVersion: number | null
  }

  export type UsersMinAggregateOutputType = {
    id: number | null
    name: string | null
    email: string | null
    password: string | null
    isVerified: boolean | null
    createdAt: Date | null
    updatedAt: Date | null
    verificationCode: string | null
    verificationCodeExpiration: Date | null
    lastVerificationRequest: Date | null
    role: $Enums.Role | null
    comunicacaocomejaca: string | null
    comunicacaomovimento: string | null
    telefone: string | null
    resetTokenVersion: number | null
  }

  export type UsersMaxAggregateOutputType = {
    id: number | null
    name: string | null
    email: string | null
    password: string | null
    isVerified: boolean | null
    createdAt: Date | null
    updatedAt: Date | null
    verificationCode: string | null
    verificationCodeExpiration: Date | null
    lastVerificationRequest: Date | null
    role: $Enums.Role | null
    comunicacaocomejaca: string | null
    comunicacaomovimento: string | null
    telefone: string | null
    resetTokenVersion: number | null
  }

  export type UsersCountAggregateOutputType = {
    id: number
    name: number
    email: number
    password: number
    isVerified: number
    createdAt: number
    updatedAt: number
    verificationCode: number
    verificationCodeExpiration: number
    lastVerificationRequest: number
    role: number
    comunicacaocomejaca: number
    comunicacaomovimento: number
    telefone: number
    resetTokenVersion: number
    _all: number
  }


  export type UsersAvgAggregateInputType = {
    id?: true
    resetTokenVersion?: true
  }

  export type UsersSumAggregateInputType = {
    id?: true
    resetTokenVersion?: true
  }

  export type UsersMinAggregateInputType = {
    id?: true
    name?: true
    email?: true
    password?: true
    isVerified?: true
    createdAt?: true
    updatedAt?: true
    verificationCode?: true
    verificationCodeExpiration?: true
    lastVerificationRequest?: true
    role?: true
    comunicacaocomejaca?: true
    comunicacaomovimento?: true
    telefone?: true
    resetTokenVersion?: true
  }

  export type UsersMaxAggregateInputType = {
    id?: true
    name?: true
    email?: true
    password?: true
    isVerified?: true
    createdAt?: true
    updatedAt?: true
    verificationCode?: true
    verificationCodeExpiration?: true
    lastVerificationRequest?: true
    role?: true
    comunicacaocomejaca?: true
    comunicacaomovimento?: true
    telefone?: true
    resetTokenVersion?: true
  }

  export type UsersCountAggregateInputType = {
    id?: true
    name?: true
    email?: true
    password?: true
    isVerified?: true
    createdAt?: true
    updatedAt?: true
    verificationCode?: true
    verificationCodeExpiration?: true
    lastVerificationRequest?: true
    role?: true
    comunicacaocomejaca?: true
    comunicacaomovimento?: true
    telefone?: true
    resetTokenVersion?: true
    _all?: true
  }

  export type UsersAggregateArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Filter which Users to aggregate.
     */
    where?: UsersWhereInput
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/sorting Sorting Docs}
     * 
     * Determine the order of Users to fetch.
     */
    orderBy?: UsersOrderByWithRelationInput | UsersOrderByWithRelationInput[]
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination#cursor-based-pagination Cursor Docs}
     * 
     * Sets the start position
     */
    cursor?: UsersWhereUniqueInput
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination Pagination Docs}
     * 
     * Take `±n` Users from the position of the cursor.
     */
    take?: number
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination Pagination Docs}
     * 
     * Skip the first `n` Users.
     */
    skip?: number
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/aggregations Aggregation Docs}
     * 
     * Count returned Users
    **/
    _count?: true | UsersCountAggregateInputType
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/aggregations Aggregation Docs}
     * 
     * Select which fields to average
    **/
    _avg?: UsersAvgAggregateInputType
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/aggregations Aggregation Docs}
     * 
     * Select which fields to sum
    **/
    _sum?: UsersSumAggregateInputType
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/aggregations Aggregation Docs}
     * 
     * Select which fields to find the minimum value
    **/
    _min?: UsersMinAggregateInputType
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/aggregations Aggregation Docs}
     * 
     * Select which fields to find the maximum value
    **/
    _max?: UsersMaxAggregateInputType
  }

  export type GetUsersAggregateType<T extends UsersAggregateArgs> = {
        [P in keyof T & keyof AggregateUsers]: P extends '_count' | 'count'
      ? T[P] extends true
        ? number
        : GetScalarType<T[P], AggregateUsers[P]>
      : GetScalarType<T[P], AggregateUsers[P]>
  }




  export type UsersGroupByArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    where?: UsersWhereInput
    orderBy?: UsersOrderByWithAggregationInput | UsersOrderByWithAggregationInput[]
    by: UsersScalarFieldEnum[] | UsersScalarFieldEnum
    having?: UsersScalarWhereWithAggregatesInput
    take?: number
    skip?: number
    _count?: UsersCountAggregateInputType | true
    _avg?: UsersAvgAggregateInputType
    _sum?: UsersSumAggregateInputType
    _min?: UsersMinAggregateInputType
    _max?: UsersMaxAggregateInputType
  }

  export type UsersGroupByOutputType = {
    id: number
    name: string
    email: string
    password: string
    isVerified: boolean
    createdAt: Date
    updatedAt: Date
    verificationCode: string | null
    verificationCodeExpiration: Date | null
    lastVerificationRequest: Date
    role: $Enums.Role
    comunicacaocomejaca: string | null
    comunicacaomovimento: string | null
    telefone: string | null
    resetTokenVersion: number
    _count: UsersCountAggregateOutputType | null
    _avg: UsersAvgAggregateOutputType | null
    _sum: UsersSumAggregateOutputType | null
    _min: UsersMinAggregateOutputType | null
    _max: UsersMaxAggregateOutputType | null
  }

  type GetUsersGroupByPayload<T extends UsersGroupByArgs> = Prisma.PrismaPromise<
    Array<
      PickEnumerable<UsersGroupByOutputType, T['by']> &
        {
          [P in ((keyof T) & (keyof UsersGroupByOutputType))]: P extends '_count'
            ? T[P] extends boolean
              ? number
              : GetScalarType<T[P], UsersGroupByOutputType[P]>
            : GetScalarType<T[P], UsersGroupByOutputType[P]>
        }
      >
    >


  export type UsersSelect<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = $Extensions.GetSelect<{
    id?: boolean
    name?: boolean
    email?: boolean
    password?: boolean
    isVerified?: boolean
    createdAt?: boolean
    updatedAt?: boolean
    verificationCode?: boolean
    verificationCodeExpiration?: boolean
    lastVerificationRequest?: boolean
    role?: boolean
    comunicacaocomejaca?: boolean
    comunicacaomovimento?: boolean
    telefone?: boolean
    resetTokenVersion?: boolean
    instituicoesAtualizadas?: boolean | Users$instituicoesAtualizadasArgs<ExtArgs>
    instituicoesCriadas?: boolean | Users$instituicoesCriadasArgs<ExtArgs>
    Participante2025?: boolean | Users$Participante2025Args<ExtArgs>
    instituicoes?: boolean | Users$instituicoesArgs<ExtArgs>
    passwordResetTokens?: boolean | Users$passwordResetTokensArgs<ExtArgs>
    _count?: boolean | UsersCountOutputTypeDefaultArgs<ExtArgs>
  }, ExtArgs["result"]["users"]>

  export type UsersSelectCreateManyAndReturn<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = $Extensions.GetSelect<{
    id?: boolean
    name?: boolean
    email?: boolean
    password?: boolean
    isVerified?: boolean
    createdAt?: boolean
    updatedAt?: boolean
    verificationCode?: boolean
    verificationCodeExpiration?: boolean
    lastVerificationRequest?: boolean
    role?: boolean
    comunicacaocomejaca?: boolean
    comunicacaomovimento?: boolean
    telefone?: boolean
    resetTokenVersion?: boolean
  }, ExtArgs["result"]["users"]>

  export type UsersSelectUpdateManyAndReturn<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = $Extensions.GetSelect<{
    id?: boolean
    name?: boolean
    email?: boolean
    password?: boolean
    isVerified?: boolean
    createdAt?: boolean
    updatedAt?: boolean
    verificationCode?: boolean
    verificationCodeExpiration?: boolean
    lastVerificationRequest?: boolean
    role?: boolean
    comunicacaocomejaca?: boolean
    comunicacaomovimento?: boolean
    telefone?: boolean
    resetTokenVersion?: boolean
  }, ExtArgs["result"]["users"]>

  export type UsersSelectScalar = {
    id?: boolean
    name?: boolean
    email?: boolean
    password?: boolean
    isVerified?: boolean
    createdAt?: boolean
    updatedAt?: boolean
    verificationCode?: boolean
    verificationCodeExpiration?: boolean
    lastVerificationRequest?: boolean
    role?: boolean
    comunicacaocomejaca?: boolean
    comunicacaomovimento?: boolean
    telefone?: boolean
    resetTokenVersion?: boolean
  }

  export type UsersOmit<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = $Extensions.GetOmit<"id" | "name" | "email" | "password" | "isVerified" | "createdAt" | "updatedAt" | "verificationCode" | "verificationCodeExpiration" | "lastVerificationRequest" | "role" | "comunicacaocomejaca" | "comunicacaomovimento" | "telefone" | "resetTokenVersion", ExtArgs["result"]["users"]>
  export type UsersInclude<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    instituicoesAtualizadas?: boolean | Users$instituicoesAtualizadasArgs<ExtArgs>
    instituicoesCriadas?: boolean | Users$instituicoesCriadasArgs<ExtArgs>
    Participante2025?: boolean | Users$Participante2025Args<ExtArgs>
    instituicoes?: boolean | Users$instituicoesArgs<ExtArgs>
    passwordResetTokens?: boolean | Users$passwordResetTokensArgs<ExtArgs>
    _count?: boolean | UsersCountOutputTypeDefaultArgs<ExtArgs>
  }
  export type UsersIncludeCreateManyAndReturn<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {}
  export type UsersIncludeUpdateManyAndReturn<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {}

  export type $UsersPayload<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    name: "Users"
    objects: {
      instituicoesAtualizadas: Prisma.$InstituicaoEspiritaPayload<ExtArgs>[]
      instituicoesCriadas: Prisma.$InstituicaoEspiritaPayload<ExtArgs>[]
      Participante2025: Prisma.$Participante2025Payload<ExtArgs>[]
      instituicoes: Prisma.$InstituicaoEspiritaPayload<ExtArgs>[]
      passwordResetTokens: Prisma.$PasswordResetTokenPayload<ExtArgs>[]
    }
    scalars: $Extensions.GetPayloadResult<{
      id: number
      name: string
      email: string
      password: string
      isVerified: boolean
      createdAt: Date
      updatedAt: Date
      verificationCode: string | null
      verificationCodeExpiration: Date | null
      lastVerificationRequest: Date
      role: $Enums.Role
      comunicacaocomejaca: string | null
      comunicacaomovimento: string | null
      telefone: string | null
      resetTokenVersion: number
    }, ExtArgs["result"]["users"]>
    composites: {}
  }

  type UsersGetPayload<S extends boolean | null | undefined | UsersDefaultArgs> = $Result.GetResult<Prisma.$UsersPayload, S>

  type UsersCountArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> =
    Omit<UsersFindManyArgs, 'select' | 'include' | 'distinct' | 'omit'> & {
      select?: UsersCountAggregateInputType | true
    }

  export interface UsersDelegate<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs, GlobalOmitOptions = {}> {
    [K: symbol]: { types: Prisma.TypeMap<ExtArgs>['model']['Users'], meta: { name: 'Users' } }
    /**
     * Find zero or one Users that matches the filter.
     * @param {UsersFindUniqueArgs} args - Arguments to find a Users
     * @example
     * // Get one Users
     * const users = await prisma.users.findUnique({
     *   where: {
     *     // ... provide filter here
     *   }
     * })
     */
    findUnique<T extends UsersFindUniqueArgs>(args: SelectSubset<T, UsersFindUniqueArgs<ExtArgs>>): Prisma__UsersClient<$Result.GetResult<Prisma.$UsersPayload<ExtArgs>, T, "findUnique", GlobalOmitOptions> | null, null, ExtArgs, GlobalOmitOptions>

    /**
     * Find one Users that matches the filter or throw an error with `error.code='P2025'`
     * if no matches were found.
     * @param {UsersFindUniqueOrThrowArgs} args - Arguments to find a Users
     * @example
     * // Get one Users
     * const users = await prisma.users.findUniqueOrThrow({
     *   where: {
     *     // ... provide filter here
     *   }
     * })
     */
    findUniqueOrThrow<T extends UsersFindUniqueOrThrowArgs>(args: SelectSubset<T, UsersFindUniqueOrThrowArgs<ExtArgs>>): Prisma__UsersClient<$Result.GetResult<Prisma.$UsersPayload<ExtArgs>, T, "findUniqueOrThrow", GlobalOmitOptions>, never, ExtArgs, GlobalOmitOptions>

    /**
     * Find the first Users that matches the filter.
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * @param {UsersFindFirstArgs} args - Arguments to find a Users
     * @example
     * // Get one Users
     * const users = await prisma.users.findFirst({
     *   where: {
     *     // ... provide filter here
     *   }
     * })
     */
    findFirst<T extends UsersFindFirstArgs>(args?: SelectSubset<T, UsersFindFirstArgs<ExtArgs>>): Prisma__UsersClient<$Result.GetResult<Prisma.$UsersPayload<ExtArgs>, T, "findFirst", GlobalOmitOptions> | null, null, ExtArgs, GlobalOmitOptions>

    /**
     * Find the first Users that matches the filter or
     * throw `PrismaKnownClientError` with `P2025` code if no matches were found.
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * @param {UsersFindFirstOrThrowArgs} args - Arguments to find a Users
     * @example
     * // Get one Users
     * const users = await prisma.users.findFirstOrThrow({
     *   where: {
     *     // ... provide filter here
     *   }
     * })
     */
    findFirstOrThrow<T extends UsersFindFirstOrThrowArgs>(args?: SelectSubset<T, UsersFindFirstOrThrowArgs<ExtArgs>>): Prisma__UsersClient<$Result.GetResult<Prisma.$UsersPayload<ExtArgs>, T, "findFirstOrThrow", GlobalOmitOptions>, never, ExtArgs, GlobalOmitOptions>

    /**
     * Find zero or more Users that matches the filter.
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * @param {UsersFindManyArgs} args - Arguments to filter and select certain fields only.
     * @example
     * // Get all Users
     * const users = await prisma.users.findMany()
     * 
     * // Get first 10 Users
     * const users = await prisma.users.findMany({ take: 10 })
     * 
     * // Only select the `id`
     * const usersWithIdOnly = await prisma.users.findMany({ select: { id: true } })
     * 
     */
    findMany<T extends UsersFindManyArgs>(args?: SelectSubset<T, UsersFindManyArgs<ExtArgs>>): Prisma.PrismaPromise<$Result.GetResult<Prisma.$UsersPayload<ExtArgs>, T, "findMany", GlobalOmitOptions>>

    /**
     * Create a Users.
     * @param {UsersCreateArgs} args - Arguments to create a Users.
     * @example
     * // Create one Users
     * const Users = await prisma.users.create({
     *   data: {
     *     // ... data to create a Users
     *   }
     * })
     * 
     */
    create<T extends UsersCreateArgs>(args: SelectSubset<T, UsersCreateArgs<ExtArgs>>): Prisma__UsersClient<$Result.GetResult<Prisma.$UsersPayload<ExtArgs>, T, "create", GlobalOmitOptions>, never, ExtArgs, GlobalOmitOptions>

    /**
     * Create many Users.
     * @param {UsersCreateManyArgs} args - Arguments to create many Users.
     * @example
     * // Create many Users
     * const users = await prisma.users.createMany({
     *   data: [
     *     // ... provide data here
     *   ]
     * })
     *     
     */
    createMany<T extends UsersCreateManyArgs>(args?: SelectSubset<T, UsersCreateManyArgs<ExtArgs>>): Prisma.PrismaPromise<BatchPayload>

    /**
     * Create many Users and returns the data saved in the database.
     * @param {UsersCreateManyAndReturnArgs} args - Arguments to create many Users.
     * @example
     * // Create many Users
     * const users = await prisma.users.createManyAndReturn({
     *   data: [
     *     // ... provide data here
     *   ]
     * })
     * 
     * // Create many Users and only return the `id`
     * const usersWithIdOnly = await prisma.users.createManyAndReturn({
     *   select: { id: true },
     *   data: [
     *     // ... provide data here
     *   ]
     * })
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * 
     */
    createManyAndReturn<T extends UsersCreateManyAndReturnArgs>(args?: SelectSubset<T, UsersCreateManyAndReturnArgs<ExtArgs>>): Prisma.PrismaPromise<$Result.GetResult<Prisma.$UsersPayload<ExtArgs>, T, "createManyAndReturn", GlobalOmitOptions>>

    /**
     * Delete a Users.
     * @param {UsersDeleteArgs} args - Arguments to delete one Users.
     * @example
     * // Delete one Users
     * const Users = await prisma.users.delete({
     *   where: {
     *     // ... filter to delete one Users
     *   }
     * })
     * 
     */
    delete<T extends UsersDeleteArgs>(args: SelectSubset<T, UsersDeleteArgs<ExtArgs>>): Prisma__UsersClient<$Result.GetResult<Prisma.$UsersPayload<ExtArgs>, T, "delete", GlobalOmitOptions>, never, ExtArgs, GlobalOmitOptions>

    /**
     * Update one Users.
     * @param {UsersUpdateArgs} args - Arguments to update one Users.
     * @example
     * // Update one Users
     * const users = await prisma.users.update({
     *   where: {
     *     // ... provide filter here
     *   },
     *   data: {
     *     // ... provide data here
     *   }
     * })
     * 
     */
    update<T extends UsersUpdateArgs>(args: SelectSubset<T, UsersUpdateArgs<ExtArgs>>): Prisma__UsersClient<$Result.GetResult<Prisma.$UsersPayload<ExtArgs>, T, "update", GlobalOmitOptions>, never, ExtArgs, GlobalOmitOptions>

    /**
     * Delete zero or more Users.
     * @param {UsersDeleteManyArgs} args - Arguments to filter Users to delete.
     * @example
     * // Delete a few Users
     * const { count } = await prisma.users.deleteMany({
     *   where: {
     *     // ... provide filter here
     *   }
     * })
     * 
     */
    deleteMany<T extends UsersDeleteManyArgs>(args?: SelectSubset<T, UsersDeleteManyArgs<ExtArgs>>): Prisma.PrismaPromise<BatchPayload>

    /**
     * Update zero or more Users.
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * @param {UsersUpdateManyArgs} args - Arguments to update one or more rows.
     * @example
     * // Update many Users
     * const users = await prisma.users.updateMany({
     *   where: {
     *     // ... provide filter here
     *   },
     *   data: {
     *     // ... provide data here
     *   }
     * })
     * 
     */
    updateMany<T extends UsersUpdateManyArgs>(args: SelectSubset<T, UsersUpdateManyArgs<ExtArgs>>): Prisma.PrismaPromise<BatchPayload>

    /**
     * Update zero or more Users and returns the data updated in the database.
     * @param {UsersUpdateManyAndReturnArgs} args - Arguments to update many Users.
     * @example
     * // Update many Users
     * const users = await prisma.users.updateManyAndReturn({
     *   where: {
     *     // ... provide filter here
     *   },
     *   data: [
     *     // ... provide data here
     *   ]
     * })
     * 
     * // Update zero or more Users and only return the `id`
     * const usersWithIdOnly = await prisma.users.updateManyAndReturn({
     *   select: { id: true },
     *   where: {
     *     // ... provide filter here
     *   },
     *   data: [
     *     // ... provide data here
     *   ]
     * })
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * 
     */
    updateManyAndReturn<T extends UsersUpdateManyAndReturnArgs>(args: SelectSubset<T, UsersUpdateManyAndReturnArgs<ExtArgs>>): Prisma.PrismaPromise<$Result.GetResult<Prisma.$UsersPayload<ExtArgs>, T, "updateManyAndReturn", GlobalOmitOptions>>

    /**
     * Create or update one Users.
     * @param {UsersUpsertArgs} args - Arguments to update or create a Users.
     * @example
     * // Update or create a Users
     * const users = await prisma.users.upsert({
     *   create: {
     *     // ... data to create a Users
     *   },
     *   update: {
     *     // ... in case it already exists, update
     *   },
     *   where: {
     *     // ... the filter for the Users we want to update
     *   }
     * })
     */
    upsert<T extends UsersUpsertArgs>(args: SelectSubset<T, UsersUpsertArgs<ExtArgs>>): Prisma__UsersClient<$Result.GetResult<Prisma.$UsersPayload<ExtArgs>, T, "upsert", GlobalOmitOptions>, never, ExtArgs, GlobalOmitOptions>


    /**
     * Count the number of Users.
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * @param {UsersCountArgs} args - Arguments to filter Users to count.
     * @example
     * // Count the number of Users
     * const count = await prisma.users.count({
     *   where: {
     *     // ... the filter for the Users we want to count
     *   }
     * })
    **/
    count<T extends UsersCountArgs>(
      args?: Subset<T, UsersCountArgs>,
    ): Prisma.PrismaPromise<
      T extends $Utils.Record<'select', any>
        ? T['select'] extends true
          ? number
          : GetScalarType<T['select'], UsersCountAggregateOutputType>
        : number
    >

    /**
     * Allows you to perform aggregations operations on a Users.
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * @param {UsersAggregateArgs} args - Select which aggregations you would like to apply and on what fields.
     * @example
     * // Ordered by age ascending
     * // Where email contains prisma.io
     * // Limited to the 10 users
     * const aggregations = await prisma.user.aggregate({
     *   _avg: {
     *     age: true,
     *   },
     *   where: {
     *     email: {
     *       contains: "prisma.io",
     *     },
     *   },
     *   orderBy: {
     *     age: "asc",
     *   },
     *   take: 10,
     * })
    **/
    aggregate<T extends UsersAggregateArgs>(args: Subset<T, UsersAggregateArgs>): Prisma.PrismaPromise<GetUsersAggregateType<T>>

    /**
     * Group by Users.
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * @param {UsersGroupByArgs} args - Group by arguments.
     * @example
     * // Group by city, order by createdAt, get count
     * const result = await prisma.user.groupBy({
     *   by: ['city', 'createdAt'],
     *   orderBy: {
     *     createdAt: true
     *   },
     *   _count: {
     *     _all: true
     *   },
     * })
     * 
    **/
    groupBy<
      T extends UsersGroupByArgs,
      HasSelectOrTake extends Or<
        Extends<'skip', Keys<T>>,
        Extends<'take', Keys<T>>
      >,
      OrderByArg extends True extends HasSelectOrTake
        ? { orderBy: UsersGroupByArgs['orderBy'] }
        : { orderBy?: UsersGroupByArgs['orderBy'] },
      OrderFields extends ExcludeUnderscoreKeys<Keys<MaybeTupleToUnion<T['orderBy']>>>,
      ByFields extends MaybeTupleToUnion<T['by']>,
      ByValid extends Has<ByFields, OrderFields>,
      HavingFields extends GetHavingFields<T['having']>,
      HavingValid extends Has<ByFields, HavingFields>,
      ByEmpty extends T['by'] extends never[] ? True : False,
      InputErrors extends ByEmpty extends True
      ? `Error: "by" must not be empty.`
      : HavingValid extends False
      ? {
          [P in HavingFields]: P extends ByFields
            ? never
            : P extends string
            ? `Error: Field "${P}" used in "having" needs to be provided in "by".`
            : [
                Error,
                'Field ',
                P,
                ` in "having" needs to be provided in "by"`,
              ]
        }[HavingFields]
      : 'take' extends Keys<T>
      ? 'orderBy' extends Keys<T>
        ? ByValid extends True
          ? {}
          : {
              [P in OrderFields]: P extends ByFields
                ? never
                : `Error: Field "${P}" in "orderBy" needs to be provided in "by"`
            }[OrderFields]
        : 'Error: If you provide "take", you also need to provide "orderBy"'
      : 'skip' extends Keys<T>
      ? 'orderBy' extends Keys<T>
        ? ByValid extends True
          ? {}
          : {
              [P in OrderFields]: P extends ByFields
                ? never
                : `Error: Field "${P}" in "orderBy" needs to be provided in "by"`
            }[OrderFields]
        : 'Error: If you provide "skip", you also need to provide "orderBy"'
      : ByValid extends True
      ? {}
      : {
          [P in OrderFields]: P extends ByFields
            ? never
            : `Error: Field "${P}" in "orderBy" needs to be provided in "by"`
        }[OrderFields]
    >(args: SubsetIntersection<T, UsersGroupByArgs, OrderByArg> & InputErrors): {} extends InputErrors ? GetUsersGroupByPayload<T> : Prisma.PrismaPromise<InputErrors>
  /**
   * Fields of the Users model
   */
  readonly fields: UsersFieldRefs;
  }

  /**
   * The delegate class that acts as a "Promise-like" for Users.
   * Why is this prefixed with `Prisma__`?
   * Because we want to prevent naming conflicts as mentioned in
   * https://github.com/prisma/prisma-client-js/issues/707
   */
  export interface Prisma__UsersClient<T, Null = never, ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs, GlobalOmitOptions = {}> extends Prisma.PrismaPromise<T> {
    readonly [Symbol.toStringTag]: "PrismaPromise"
    instituicoesAtualizadas<T extends Users$instituicoesAtualizadasArgs<ExtArgs> = {}>(args?: Subset<T, Users$instituicoesAtualizadasArgs<ExtArgs>>): Prisma.PrismaPromise<$Result.GetResult<Prisma.$InstituicaoEspiritaPayload<ExtArgs>, T, "findMany", GlobalOmitOptions> | Null>
    instituicoesCriadas<T extends Users$instituicoesCriadasArgs<ExtArgs> = {}>(args?: Subset<T, Users$instituicoesCriadasArgs<ExtArgs>>): Prisma.PrismaPromise<$Result.GetResult<Prisma.$InstituicaoEspiritaPayload<ExtArgs>, T, "findMany", GlobalOmitOptions> | Null>
    Participante2025<T extends Users$Participante2025Args<ExtArgs> = {}>(args?: Subset<T, Users$Participante2025Args<ExtArgs>>): Prisma.PrismaPromise<$Result.GetResult<Prisma.$Participante2025Payload<ExtArgs>, T, "findMany", GlobalOmitOptions> | Null>
    instituicoes<T extends Users$instituicoesArgs<ExtArgs> = {}>(args?: Subset<T, Users$instituicoesArgs<ExtArgs>>): Prisma.PrismaPromise<$Result.GetResult<Prisma.$InstituicaoEspiritaPayload<ExtArgs>, T, "findMany", GlobalOmitOptions> | Null>
    passwordResetTokens<T extends Users$passwordResetTokensArgs<ExtArgs> = {}>(args?: Subset<T, Users$passwordResetTokensArgs<ExtArgs>>): Prisma.PrismaPromise<$Result.GetResult<Prisma.$PasswordResetTokenPayload<ExtArgs>, T, "findMany", GlobalOmitOptions> | Null>
    /**
     * Attaches callbacks for the resolution and/or rejection of the Promise.
     * @param onfulfilled The callback to execute when the Promise is resolved.
     * @param onrejected The callback to execute when the Promise is rejected.
     * @returns A Promise for the completion of which ever callback is executed.
     */
    then<TResult1 = T, TResult2 = never>(onfulfilled?: ((value: T) => TResult1 | PromiseLike<TResult1>) | undefined | null, onrejected?: ((reason: any) => TResult2 | PromiseLike<TResult2>) | undefined | null): $Utils.JsPromise<TResult1 | TResult2>
    /**
     * Attaches a callback for only the rejection of the Promise.
     * @param onrejected The callback to execute when the Promise is rejected.
     * @returns A Promise for the completion of the callback.
     */
    catch<TResult = never>(onrejected?: ((reason: any) => TResult | PromiseLike<TResult>) | undefined | null): $Utils.JsPromise<T | TResult>
    /**
     * Attaches a callback that is invoked when the Promise is settled (fulfilled or rejected). The
     * resolved value cannot be modified from the callback.
     * @param onfinally The callback to execute when the Promise is settled (fulfilled or rejected).
     * @returns A Promise for the completion of the callback.
     */
    finally(onfinally?: (() => void) | undefined | null): $Utils.JsPromise<T>
  }




  /**
   * Fields of the Users model
   */
  interface UsersFieldRefs {
    readonly id: FieldRef<"Users", 'Int'>
    readonly name: FieldRef<"Users", 'String'>
    readonly email: FieldRef<"Users", 'String'>
    readonly password: FieldRef<"Users", 'String'>
    readonly isVerified: FieldRef<"Users", 'Boolean'>
    readonly createdAt: FieldRef<"Users", 'DateTime'>
    readonly updatedAt: FieldRef<"Users", 'DateTime'>
    readonly verificationCode: FieldRef<"Users", 'String'>
    readonly verificationCodeExpiration: FieldRef<"Users", 'DateTime'>
    readonly lastVerificationRequest: FieldRef<"Users", 'DateTime'>
    readonly role: FieldRef<"Users", 'Role'>
    readonly comunicacaocomejaca: FieldRef<"Users", 'String'>
    readonly comunicacaomovimento: FieldRef<"Users", 'String'>
    readonly telefone: FieldRef<"Users", 'String'>
    readonly resetTokenVersion: FieldRef<"Users", 'Int'>
  }
    

  // Custom InputTypes
  /**
   * Users findUnique
   */
  export type UsersFindUniqueArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the Users
     */
    select?: UsersSelect<ExtArgs> | null
    /**
     * Omit specific fields from the Users
     */
    omit?: UsersOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: UsersInclude<ExtArgs> | null
    /**
     * Filter, which Users to fetch.
     */
    where: UsersWhereUniqueInput
  }

  /**
   * Users findUniqueOrThrow
   */
  export type UsersFindUniqueOrThrowArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the Users
     */
    select?: UsersSelect<ExtArgs> | null
    /**
     * Omit specific fields from the Users
     */
    omit?: UsersOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: UsersInclude<ExtArgs> | null
    /**
     * Filter, which Users to fetch.
     */
    where: UsersWhereUniqueInput
  }

  /**
   * Users findFirst
   */
  export type UsersFindFirstArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the Users
     */
    select?: UsersSelect<ExtArgs> | null
    /**
     * Omit specific fields from the Users
     */
    omit?: UsersOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: UsersInclude<ExtArgs> | null
    /**
     * Filter, which Users to fetch.
     */
    where?: UsersWhereInput
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/sorting Sorting Docs}
     * 
     * Determine the order of Users to fetch.
     */
    orderBy?: UsersOrderByWithRelationInput | UsersOrderByWithRelationInput[]
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination#cursor-based-pagination Cursor Docs}
     * 
     * Sets the position for searching for Users.
     */
    cursor?: UsersWhereUniqueInput
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination Pagination Docs}
     * 
     * Take `±n` Users from the position of the cursor.
     */
    take?: number
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination Pagination Docs}
     * 
     * Skip the first `n` Users.
     */
    skip?: number
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/distinct Distinct Docs}
     * 
     * Filter by unique combinations of Users.
     */
    distinct?: UsersScalarFieldEnum | UsersScalarFieldEnum[]
  }

  /**
   * Users findFirstOrThrow
   */
  export type UsersFindFirstOrThrowArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the Users
     */
    select?: UsersSelect<ExtArgs> | null
    /**
     * Omit specific fields from the Users
     */
    omit?: UsersOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: UsersInclude<ExtArgs> | null
    /**
     * Filter, which Users to fetch.
     */
    where?: UsersWhereInput
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/sorting Sorting Docs}
     * 
     * Determine the order of Users to fetch.
     */
    orderBy?: UsersOrderByWithRelationInput | UsersOrderByWithRelationInput[]
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination#cursor-based-pagination Cursor Docs}
     * 
     * Sets the position for searching for Users.
     */
    cursor?: UsersWhereUniqueInput
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination Pagination Docs}
     * 
     * Take `±n` Users from the position of the cursor.
     */
    take?: number
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination Pagination Docs}
     * 
     * Skip the first `n` Users.
     */
    skip?: number
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/distinct Distinct Docs}
     * 
     * Filter by unique combinations of Users.
     */
    distinct?: UsersScalarFieldEnum | UsersScalarFieldEnum[]
  }

  /**
   * Users findMany
   */
  export type UsersFindManyArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the Users
     */
    select?: UsersSelect<ExtArgs> | null
    /**
     * Omit specific fields from the Users
     */
    omit?: UsersOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: UsersInclude<ExtArgs> | null
    /**
     * Filter, which Users to fetch.
     */
    where?: UsersWhereInput
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/sorting Sorting Docs}
     * 
     * Determine the order of Users to fetch.
     */
    orderBy?: UsersOrderByWithRelationInput | UsersOrderByWithRelationInput[]
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination#cursor-based-pagination Cursor Docs}
     * 
     * Sets the position for listing Users.
     */
    cursor?: UsersWhereUniqueInput
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination Pagination Docs}
     * 
     * Take `±n` Users from the position of the cursor.
     */
    take?: number
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination Pagination Docs}
     * 
     * Skip the first `n` Users.
     */
    skip?: number
    distinct?: UsersScalarFieldEnum | UsersScalarFieldEnum[]
  }

  /**
   * Users create
   */
  export type UsersCreateArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the Users
     */
    select?: UsersSelect<ExtArgs> | null
    /**
     * Omit specific fields from the Users
     */
    omit?: UsersOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: UsersInclude<ExtArgs> | null
    /**
     * The data needed to create a Users.
     */
    data: XOR<UsersCreateInput, UsersUncheckedCreateInput>
  }

  /**
   * Users createMany
   */
  export type UsersCreateManyArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * The data used to create many Users.
     */
    data: UsersCreateManyInput | UsersCreateManyInput[]
    skipDuplicates?: boolean
  }

  /**
   * Users createManyAndReturn
   */
  export type UsersCreateManyAndReturnArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the Users
     */
    select?: UsersSelectCreateManyAndReturn<ExtArgs> | null
    /**
     * Omit specific fields from the Users
     */
    omit?: UsersOmit<ExtArgs> | null
    /**
     * The data used to create many Users.
     */
    data: UsersCreateManyInput | UsersCreateManyInput[]
    skipDuplicates?: boolean
  }

  /**
   * Users update
   */
  export type UsersUpdateArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the Users
     */
    select?: UsersSelect<ExtArgs> | null
    /**
     * Omit specific fields from the Users
     */
    omit?: UsersOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: UsersInclude<ExtArgs> | null
    /**
     * The data needed to update a Users.
     */
    data: XOR<UsersUpdateInput, UsersUncheckedUpdateInput>
    /**
     * Choose, which Users to update.
     */
    where: UsersWhereUniqueInput
  }

  /**
   * Users updateMany
   */
  export type UsersUpdateManyArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * The data used to update Users.
     */
    data: XOR<UsersUpdateManyMutationInput, UsersUncheckedUpdateManyInput>
    /**
     * Filter which Users to update
     */
    where?: UsersWhereInput
    /**
     * Limit how many Users to update.
     */
    limit?: number
  }

  /**
   * Users updateManyAndReturn
   */
  export type UsersUpdateManyAndReturnArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the Users
     */
    select?: UsersSelectUpdateManyAndReturn<ExtArgs> | null
    /**
     * Omit specific fields from the Users
     */
    omit?: UsersOmit<ExtArgs> | null
    /**
     * The data used to update Users.
     */
    data: XOR<UsersUpdateManyMutationInput, UsersUncheckedUpdateManyInput>
    /**
     * Filter which Users to update
     */
    where?: UsersWhereInput
    /**
     * Limit how many Users to update.
     */
    limit?: number
  }

  /**
   * Users upsert
   */
  export type UsersUpsertArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the Users
     */
    select?: UsersSelect<ExtArgs> | null
    /**
     * Omit specific fields from the Users
     */
    omit?: UsersOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: UsersInclude<ExtArgs> | null
    /**
     * The filter to search for the Users to update in case it exists.
     */
    where: UsersWhereUniqueInput
    /**
     * In case the Users found by the `where` argument doesn't exist, create a new Users with this data.
     */
    create: XOR<UsersCreateInput, UsersUncheckedCreateInput>
    /**
     * In case the Users was found with the provided `where` argument, update it with this data.
     */
    update: XOR<UsersUpdateInput, UsersUncheckedUpdateInput>
  }

  /**
   * Users delete
   */
  export type UsersDeleteArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the Users
     */
    select?: UsersSelect<ExtArgs> | null
    /**
     * Omit specific fields from the Users
     */
    omit?: UsersOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: UsersInclude<ExtArgs> | null
    /**
     * Filter which Users to delete.
     */
    where: UsersWhereUniqueInput
  }

  /**
   * Users deleteMany
   */
  export type UsersDeleteManyArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Filter which Users to delete
     */
    where?: UsersWhereInput
    /**
     * Limit how many Users to delete.
     */
    limit?: number
  }

  /**
   * Users.instituicoesAtualizadas
   */
  export type Users$instituicoesAtualizadasArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the InstituicaoEspirita
     */
    select?: InstituicaoEspiritaSelect<ExtArgs> | null
    /**
     * Omit specific fields from the InstituicaoEspirita
     */
    omit?: InstituicaoEspiritaOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: InstituicaoEspiritaInclude<ExtArgs> | null
    where?: InstituicaoEspiritaWhereInput
    orderBy?: InstituicaoEspiritaOrderByWithRelationInput | InstituicaoEspiritaOrderByWithRelationInput[]
    cursor?: InstituicaoEspiritaWhereUniqueInput
    take?: number
    skip?: number
    distinct?: InstituicaoEspiritaScalarFieldEnum | InstituicaoEspiritaScalarFieldEnum[]
  }

  /**
   * Users.instituicoesCriadas
   */
  export type Users$instituicoesCriadasArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the InstituicaoEspirita
     */
    select?: InstituicaoEspiritaSelect<ExtArgs> | null
    /**
     * Omit specific fields from the InstituicaoEspirita
     */
    omit?: InstituicaoEspiritaOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: InstituicaoEspiritaInclude<ExtArgs> | null
    where?: InstituicaoEspiritaWhereInput
    orderBy?: InstituicaoEspiritaOrderByWithRelationInput | InstituicaoEspiritaOrderByWithRelationInput[]
    cursor?: InstituicaoEspiritaWhereUniqueInput
    take?: number
    skip?: number
    distinct?: InstituicaoEspiritaScalarFieldEnum | InstituicaoEspiritaScalarFieldEnum[]
  }

  /**
   * Users.Participante2025
   */
  export type Users$Participante2025Args<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the Participante2025
     */
    select?: Participante2025Select<ExtArgs> | null
    /**
     * Omit specific fields from the Participante2025
     */
    omit?: Participante2025Omit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: Participante2025Include<ExtArgs> | null
    where?: Participante2025WhereInput
    orderBy?: Participante2025OrderByWithRelationInput | Participante2025OrderByWithRelationInput[]
    cursor?: Participante2025WhereUniqueInput
    take?: number
    skip?: number
    distinct?: Participante2025ScalarFieldEnum | Participante2025ScalarFieldEnum[]
  }

  /**
   * Users.instituicoes
   */
  export type Users$instituicoesArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the InstituicaoEspirita
     */
    select?: InstituicaoEspiritaSelect<ExtArgs> | null
    /**
     * Omit specific fields from the InstituicaoEspirita
     */
    omit?: InstituicaoEspiritaOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: InstituicaoEspiritaInclude<ExtArgs> | null
    where?: InstituicaoEspiritaWhereInput
    orderBy?: InstituicaoEspiritaOrderByWithRelationInput | InstituicaoEspiritaOrderByWithRelationInput[]
    cursor?: InstituicaoEspiritaWhereUniqueInput
    take?: number
    skip?: number
    distinct?: InstituicaoEspiritaScalarFieldEnum | InstituicaoEspiritaScalarFieldEnum[]
  }

  /**
   * Users.passwordResetTokens
   */
  export type Users$passwordResetTokensArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the PasswordResetToken
     */
    select?: PasswordResetTokenSelect<ExtArgs> | null
    /**
     * Omit specific fields from the PasswordResetToken
     */
    omit?: PasswordResetTokenOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: PasswordResetTokenInclude<ExtArgs> | null
    where?: PasswordResetTokenWhereInput
    orderBy?: PasswordResetTokenOrderByWithRelationInput | PasswordResetTokenOrderByWithRelationInput[]
    cursor?: PasswordResetTokenWhereUniqueInput
    take?: number
    skip?: number
    distinct?: PasswordResetTokenScalarFieldEnum | PasswordResetTokenScalarFieldEnum[]
  }

  /**
   * Users without action
   */
  export type UsersDefaultArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the Users
     */
    select?: UsersSelect<ExtArgs> | null
    /**
     * Omit specific fields from the Users
     */
    omit?: UsersOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: UsersInclude<ExtArgs> | null
  }


  /**
   * Model InstituicaoEspirita
   */

  export type AggregateInstituicaoEspirita = {
    _count: InstituicaoEspiritaCountAggregateOutputType | null
    _avg: InstituicaoEspiritaAvgAggregateOutputType | null
    _sum: InstituicaoEspiritaSumAggregateOutputType | null
    _min: InstituicaoEspiritaMinAggregateOutputType | null
    _max: InstituicaoEspiritaMaxAggregateOutputType | null
  }

  export type InstituicaoEspiritaAvgAggregateOutputType = {
    id: number | null
    criadoPorId: number | null
    atualizadoPorId: number | null
  }

  export type InstituicaoEspiritaSumAggregateOutputType = {
    id: number | null
    criadoPorId: number | null
    atualizadoPorId: number | null
  }

  export type InstituicaoEspiritaMinAggregateOutputType = {
    id: number | null
    nome: string | null
    nome_CNPJ: string | null
    estado: string | null
    cidade: string | null
    bairro: string | null
    logradouro: string | null
    numero: string | null
    complemento: string | null
    telefone: string | null
    email: string | null
    createdAt: Date | null
    updatedAt: Date | null
    criadoPorId: number | null
    sigla: string | null
    CEU: string | null
    dia: string | null
    horario: string | null
    atualizadoPorId: number | null
    CNPJ: string | null
  }

  export type InstituicaoEspiritaMaxAggregateOutputType = {
    id: number | null
    nome: string | null
    nome_CNPJ: string | null
    estado: string | null
    cidade: string | null
    bairro: string | null
    logradouro: string | null
    numero: string | null
    complemento: string | null
    telefone: string | null
    email: string | null
    createdAt: Date | null
    updatedAt: Date | null
    criadoPorId: number | null
    sigla: string | null
    CEU: string | null
    dia: string | null
    horario: string | null
    atualizadoPorId: number | null
    CNPJ: string | null
  }

  export type InstituicaoEspiritaCountAggregateOutputType = {
    id: number
    nome: number
    nome_CNPJ: number
    estado: number
    cidade: number
    bairro: number
    logradouro: number
    numero: number
    complemento: number
    telefone: number
    email: number
    createdAt: number
    updatedAt: number
    criadoPorId: number
    sigla: number
    CEU: number
    dia: number
    horario: number
    atualizadoPorId: number
    CNPJ: number
    _all: number
  }


  export type InstituicaoEspiritaAvgAggregateInputType = {
    id?: true
    criadoPorId?: true
    atualizadoPorId?: true
  }

  export type InstituicaoEspiritaSumAggregateInputType = {
    id?: true
    criadoPorId?: true
    atualizadoPorId?: true
  }

  export type InstituicaoEspiritaMinAggregateInputType = {
    id?: true
    nome?: true
    nome_CNPJ?: true
    estado?: true
    cidade?: true
    bairro?: true
    logradouro?: true
    numero?: true
    complemento?: true
    telefone?: true
    email?: true
    createdAt?: true
    updatedAt?: true
    criadoPorId?: true
    sigla?: true
    CEU?: true
    dia?: true
    horario?: true
    atualizadoPorId?: true
    CNPJ?: true
  }

  export type InstituicaoEspiritaMaxAggregateInputType = {
    id?: true
    nome?: true
    nome_CNPJ?: true
    estado?: true
    cidade?: true
    bairro?: true
    logradouro?: true
    numero?: true
    complemento?: true
    telefone?: true
    email?: true
    createdAt?: true
    updatedAt?: true
    criadoPorId?: true
    sigla?: true
    CEU?: true
    dia?: true
    horario?: true
    atualizadoPorId?: true
    CNPJ?: true
  }

  export type InstituicaoEspiritaCountAggregateInputType = {
    id?: true
    nome?: true
    nome_CNPJ?: true
    estado?: true
    cidade?: true
    bairro?: true
    logradouro?: true
    numero?: true
    complemento?: true
    telefone?: true
    email?: true
    createdAt?: true
    updatedAt?: true
    criadoPorId?: true
    sigla?: true
    CEU?: true
    dia?: true
    horario?: true
    atualizadoPorId?: true
    CNPJ?: true
    _all?: true
  }

  export type InstituicaoEspiritaAggregateArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Filter which InstituicaoEspirita to aggregate.
     */
    where?: InstituicaoEspiritaWhereInput
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/sorting Sorting Docs}
     * 
     * Determine the order of InstituicaoEspiritas to fetch.
     */
    orderBy?: InstituicaoEspiritaOrderByWithRelationInput | InstituicaoEspiritaOrderByWithRelationInput[]
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination#cursor-based-pagination Cursor Docs}
     * 
     * Sets the start position
     */
    cursor?: InstituicaoEspiritaWhereUniqueInput
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination Pagination Docs}
     * 
     * Take `±n` InstituicaoEspiritas from the position of the cursor.
     */
    take?: number
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination Pagination Docs}
     * 
     * Skip the first `n` InstituicaoEspiritas.
     */
    skip?: number
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/aggregations Aggregation Docs}
     * 
     * Count returned InstituicaoEspiritas
    **/
    _count?: true | InstituicaoEspiritaCountAggregateInputType
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/aggregations Aggregation Docs}
     * 
     * Select which fields to average
    **/
    _avg?: InstituicaoEspiritaAvgAggregateInputType
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/aggregations Aggregation Docs}
     * 
     * Select which fields to sum
    **/
    _sum?: InstituicaoEspiritaSumAggregateInputType
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/aggregations Aggregation Docs}
     * 
     * Select which fields to find the minimum value
    **/
    _min?: InstituicaoEspiritaMinAggregateInputType
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/aggregations Aggregation Docs}
     * 
     * Select which fields to find the maximum value
    **/
    _max?: InstituicaoEspiritaMaxAggregateInputType
  }

  export type GetInstituicaoEspiritaAggregateType<T extends InstituicaoEspiritaAggregateArgs> = {
        [P in keyof T & keyof AggregateInstituicaoEspirita]: P extends '_count' | 'count'
      ? T[P] extends true
        ? number
        : GetScalarType<T[P], AggregateInstituicaoEspirita[P]>
      : GetScalarType<T[P], AggregateInstituicaoEspirita[P]>
  }




  export type InstituicaoEspiritaGroupByArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    where?: InstituicaoEspiritaWhereInput
    orderBy?: InstituicaoEspiritaOrderByWithAggregationInput | InstituicaoEspiritaOrderByWithAggregationInput[]
    by: InstituicaoEspiritaScalarFieldEnum[] | InstituicaoEspiritaScalarFieldEnum
    having?: InstituicaoEspiritaScalarWhereWithAggregatesInput
    take?: number
    skip?: number
    _count?: InstituicaoEspiritaCountAggregateInputType | true
    _avg?: InstituicaoEspiritaAvgAggregateInputType
    _sum?: InstituicaoEspiritaSumAggregateInputType
    _min?: InstituicaoEspiritaMinAggregateInputType
    _max?: InstituicaoEspiritaMaxAggregateInputType
  }

  export type InstituicaoEspiritaGroupByOutputType = {
    id: number
    nome: string
    nome_CNPJ: string | null
    estado: string | null
    cidade: string | null
    bairro: string | null
    logradouro: string | null
    numero: string | null
    complemento: string | null
    telefone: string | null
    email: string | null
    createdAt: Date
    updatedAt: Date
    criadoPorId: number | null
    sigla: string
    CEU: string | null
    dia: string | null
    horario: string | null
    atualizadoPorId: number | null
    CNPJ: string
    _count: InstituicaoEspiritaCountAggregateOutputType | null
    _avg: InstituicaoEspiritaAvgAggregateOutputType | null
    _sum: InstituicaoEspiritaSumAggregateOutputType | null
    _min: InstituicaoEspiritaMinAggregateOutputType | null
    _max: InstituicaoEspiritaMaxAggregateOutputType | null
  }

  type GetInstituicaoEspiritaGroupByPayload<T extends InstituicaoEspiritaGroupByArgs> = Prisma.PrismaPromise<
    Array<
      PickEnumerable<InstituicaoEspiritaGroupByOutputType, T['by']> &
        {
          [P in ((keyof T) & (keyof InstituicaoEspiritaGroupByOutputType))]: P extends '_count'
            ? T[P] extends boolean
              ? number
              : GetScalarType<T[P], InstituicaoEspiritaGroupByOutputType[P]>
            : GetScalarType<T[P], InstituicaoEspiritaGroupByOutputType[P]>
        }
      >
    >


  export type InstituicaoEspiritaSelect<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = $Extensions.GetSelect<{
    id?: boolean
    nome?: boolean
    nome_CNPJ?: boolean
    estado?: boolean
    cidade?: boolean
    bairro?: boolean
    logradouro?: boolean
    numero?: boolean
    complemento?: boolean
    telefone?: boolean
    email?: boolean
    createdAt?: boolean
    updatedAt?: boolean
    criadoPorId?: boolean
    sigla?: boolean
    CEU?: boolean
    dia?: boolean
    horario?: boolean
    atualizadoPorId?: boolean
    CNPJ?: boolean
    atualizadoPor?: boolean | InstituicaoEspirita$atualizadoPorArgs<ExtArgs>
    criadoPor?: boolean | InstituicaoEspirita$criadoPorArgs<ExtArgs>
    Participante2025?: boolean | InstituicaoEspirita$Participante2025Args<ExtArgs>
    Users?: boolean | InstituicaoEspirita$UsersArgs<ExtArgs>
    _count?: boolean | InstituicaoEspiritaCountOutputTypeDefaultArgs<ExtArgs>
  }, ExtArgs["result"]["instituicaoEspirita"]>

  export type InstituicaoEspiritaSelectCreateManyAndReturn<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = $Extensions.GetSelect<{
    id?: boolean
    nome?: boolean
    nome_CNPJ?: boolean
    estado?: boolean
    cidade?: boolean
    bairro?: boolean
    logradouro?: boolean
    numero?: boolean
    complemento?: boolean
    telefone?: boolean
    email?: boolean
    createdAt?: boolean
    updatedAt?: boolean
    criadoPorId?: boolean
    sigla?: boolean
    CEU?: boolean
    dia?: boolean
    horario?: boolean
    atualizadoPorId?: boolean
    CNPJ?: boolean
    atualizadoPor?: boolean | InstituicaoEspirita$atualizadoPorArgs<ExtArgs>
    criadoPor?: boolean | InstituicaoEspirita$criadoPorArgs<ExtArgs>
  }, ExtArgs["result"]["instituicaoEspirita"]>

  export type InstituicaoEspiritaSelectUpdateManyAndReturn<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = $Extensions.GetSelect<{
    id?: boolean
    nome?: boolean
    nome_CNPJ?: boolean
    estado?: boolean
    cidade?: boolean
    bairro?: boolean
    logradouro?: boolean
    numero?: boolean
    complemento?: boolean
    telefone?: boolean
    email?: boolean
    createdAt?: boolean
    updatedAt?: boolean
    criadoPorId?: boolean
    sigla?: boolean
    CEU?: boolean
    dia?: boolean
    horario?: boolean
    atualizadoPorId?: boolean
    CNPJ?: boolean
    atualizadoPor?: boolean | InstituicaoEspirita$atualizadoPorArgs<ExtArgs>
    criadoPor?: boolean | InstituicaoEspirita$criadoPorArgs<ExtArgs>
  }, ExtArgs["result"]["instituicaoEspirita"]>

  export type InstituicaoEspiritaSelectScalar = {
    id?: boolean
    nome?: boolean
    nome_CNPJ?: boolean
    estado?: boolean
    cidade?: boolean
    bairro?: boolean
    logradouro?: boolean
    numero?: boolean
    complemento?: boolean
    telefone?: boolean
    email?: boolean
    createdAt?: boolean
    updatedAt?: boolean
    criadoPorId?: boolean
    sigla?: boolean
    CEU?: boolean
    dia?: boolean
    horario?: boolean
    atualizadoPorId?: boolean
    CNPJ?: boolean
  }

  export type InstituicaoEspiritaOmit<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = $Extensions.GetOmit<"id" | "nome" | "nome_CNPJ" | "estado" | "cidade" | "bairro" | "logradouro" | "numero" | "complemento" | "telefone" | "email" | "createdAt" | "updatedAt" | "criadoPorId" | "sigla" | "CEU" | "dia" | "horario" | "atualizadoPorId" | "CNPJ", ExtArgs["result"]["instituicaoEspirita"]>
  export type InstituicaoEspiritaInclude<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    atualizadoPor?: boolean | InstituicaoEspirita$atualizadoPorArgs<ExtArgs>
    criadoPor?: boolean | InstituicaoEspirita$criadoPorArgs<ExtArgs>
    Participante2025?: boolean | InstituicaoEspirita$Participante2025Args<ExtArgs>
    Users?: boolean | InstituicaoEspirita$UsersArgs<ExtArgs>
    _count?: boolean | InstituicaoEspiritaCountOutputTypeDefaultArgs<ExtArgs>
  }
  export type InstituicaoEspiritaIncludeCreateManyAndReturn<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    atualizadoPor?: boolean | InstituicaoEspirita$atualizadoPorArgs<ExtArgs>
    criadoPor?: boolean | InstituicaoEspirita$criadoPorArgs<ExtArgs>
  }
  export type InstituicaoEspiritaIncludeUpdateManyAndReturn<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    atualizadoPor?: boolean | InstituicaoEspirita$atualizadoPorArgs<ExtArgs>
    criadoPor?: boolean | InstituicaoEspirita$criadoPorArgs<ExtArgs>
  }

  export type $InstituicaoEspiritaPayload<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    name: "InstituicaoEspirita"
    objects: {
      atualizadoPor: Prisma.$UsersPayload<ExtArgs> | null
      criadoPor: Prisma.$UsersPayload<ExtArgs> | null
      Participante2025: Prisma.$Participante2025Payload<ExtArgs>[]
      Users: Prisma.$UsersPayload<ExtArgs>[]
    }
    scalars: $Extensions.GetPayloadResult<{
      id: number
      nome: string
      nome_CNPJ: string | null
      estado: string | null
      cidade: string | null
      bairro: string | null
      logradouro: string | null
      numero: string | null
      complemento: string | null
      telefone: string | null
      email: string | null
      createdAt: Date
      updatedAt: Date
      criadoPorId: number | null
      sigla: string
      CEU: string | null
      dia: string | null
      horario: string | null
      atualizadoPorId: number | null
      CNPJ: string
    }, ExtArgs["result"]["instituicaoEspirita"]>
    composites: {}
  }

  type InstituicaoEspiritaGetPayload<S extends boolean | null | undefined | InstituicaoEspiritaDefaultArgs> = $Result.GetResult<Prisma.$InstituicaoEspiritaPayload, S>

  type InstituicaoEspiritaCountArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> =
    Omit<InstituicaoEspiritaFindManyArgs, 'select' | 'include' | 'distinct' | 'omit'> & {
      select?: InstituicaoEspiritaCountAggregateInputType | true
    }

  export interface InstituicaoEspiritaDelegate<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs, GlobalOmitOptions = {}> {
    [K: symbol]: { types: Prisma.TypeMap<ExtArgs>['model']['InstituicaoEspirita'], meta: { name: 'InstituicaoEspirita' } }
    /**
     * Find zero or one InstituicaoEspirita that matches the filter.
     * @param {InstituicaoEspiritaFindUniqueArgs} args - Arguments to find a InstituicaoEspirita
     * @example
     * // Get one InstituicaoEspirita
     * const instituicaoEspirita = await prisma.instituicaoEspirita.findUnique({
     *   where: {
     *     // ... provide filter here
     *   }
     * })
     */
    findUnique<T extends InstituicaoEspiritaFindUniqueArgs>(args: SelectSubset<T, InstituicaoEspiritaFindUniqueArgs<ExtArgs>>): Prisma__InstituicaoEspiritaClient<$Result.GetResult<Prisma.$InstituicaoEspiritaPayload<ExtArgs>, T, "findUnique", GlobalOmitOptions> | null, null, ExtArgs, GlobalOmitOptions>

    /**
     * Find one InstituicaoEspirita that matches the filter or throw an error with `error.code='P2025'`
     * if no matches were found.
     * @param {InstituicaoEspiritaFindUniqueOrThrowArgs} args - Arguments to find a InstituicaoEspirita
     * @example
     * // Get one InstituicaoEspirita
     * const instituicaoEspirita = await prisma.instituicaoEspirita.findUniqueOrThrow({
     *   where: {
     *     // ... provide filter here
     *   }
     * })
     */
    findUniqueOrThrow<T extends InstituicaoEspiritaFindUniqueOrThrowArgs>(args: SelectSubset<T, InstituicaoEspiritaFindUniqueOrThrowArgs<ExtArgs>>): Prisma__InstituicaoEspiritaClient<$Result.GetResult<Prisma.$InstituicaoEspiritaPayload<ExtArgs>, T, "findUniqueOrThrow", GlobalOmitOptions>, never, ExtArgs, GlobalOmitOptions>

    /**
     * Find the first InstituicaoEspirita that matches the filter.
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * @param {InstituicaoEspiritaFindFirstArgs} args - Arguments to find a InstituicaoEspirita
     * @example
     * // Get one InstituicaoEspirita
     * const instituicaoEspirita = await prisma.instituicaoEspirita.findFirst({
     *   where: {
     *     // ... provide filter here
     *   }
     * })
     */
    findFirst<T extends InstituicaoEspiritaFindFirstArgs>(args?: SelectSubset<T, InstituicaoEspiritaFindFirstArgs<ExtArgs>>): Prisma__InstituicaoEspiritaClient<$Result.GetResult<Prisma.$InstituicaoEspiritaPayload<ExtArgs>, T, "findFirst", GlobalOmitOptions> | null, null, ExtArgs, GlobalOmitOptions>

    /**
     * Find the first InstituicaoEspirita that matches the filter or
     * throw `PrismaKnownClientError` with `P2025` code if no matches were found.
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * @param {InstituicaoEspiritaFindFirstOrThrowArgs} args - Arguments to find a InstituicaoEspirita
     * @example
     * // Get one InstituicaoEspirita
     * const instituicaoEspirita = await prisma.instituicaoEspirita.findFirstOrThrow({
     *   where: {
     *     // ... provide filter here
     *   }
     * })
     */
    findFirstOrThrow<T extends InstituicaoEspiritaFindFirstOrThrowArgs>(args?: SelectSubset<T, InstituicaoEspiritaFindFirstOrThrowArgs<ExtArgs>>): Prisma__InstituicaoEspiritaClient<$Result.GetResult<Prisma.$InstituicaoEspiritaPayload<ExtArgs>, T, "findFirstOrThrow", GlobalOmitOptions>, never, ExtArgs, GlobalOmitOptions>

    /**
     * Find zero or more InstituicaoEspiritas that matches the filter.
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * @param {InstituicaoEspiritaFindManyArgs} args - Arguments to filter and select certain fields only.
     * @example
     * // Get all InstituicaoEspiritas
     * const instituicaoEspiritas = await prisma.instituicaoEspirita.findMany()
     * 
     * // Get first 10 InstituicaoEspiritas
     * const instituicaoEspiritas = await prisma.instituicaoEspirita.findMany({ take: 10 })
     * 
     * // Only select the `id`
     * const instituicaoEspiritaWithIdOnly = await prisma.instituicaoEspirita.findMany({ select: { id: true } })
     * 
     */
    findMany<T extends InstituicaoEspiritaFindManyArgs>(args?: SelectSubset<T, InstituicaoEspiritaFindManyArgs<ExtArgs>>): Prisma.PrismaPromise<$Result.GetResult<Prisma.$InstituicaoEspiritaPayload<ExtArgs>, T, "findMany", GlobalOmitOptions>>

    /**
     * Create a InstituicaoEspirita.
     * @param {InstituicaoEspiritaCreateArgs} args - Arguments to create a InstituicaoEspirita.
     * @example
     * // Create one InstituicaoEspirita
     * const InstituicaoEspirita = await prisma.instituicaoEspirita.create({
     *   data: {
     *     // ... data to create a InstituicaoEspirita
     *   }
     * })
     * 
     */
    create<T extends InstituicaoEspiritaCreateArgs>(args: SelectSubset<T, InstituicaoEspiritaCreateArgs<ExtArgs>>): Prisma__InstituicaoEspiritaClient<$Result.GetResult<Prisma.$InstituicaoEspiritaPayload<ExtArgs>, T, "create", GlobalOmitOptions>, never, ExtArgs, GlobalOmitOptions>

    /**
     * Create many InstituicaoEspiritas.
     * @param {InstituicaoEspiritaCreateManyArgs} args - Arguments to create many InstituicaoEspiritas.
     * @example
     * // Create many InstituicaoEspiritas
     * const instituicaoEspirita = await prisma.instituicaoEspirita.createMany({
     *   data: [
     *     // ... provide data here
     *   ]
     * })
     *     
     */
    createMany<T extends InstituicaoEspiritaCreateManyArgs>(args?: SelectSubset<T, InstituicaoEspiritaCreateManyArgs<ExtArgs>>): Prisma.PrismaPromise<BatchPayload>

    /**
     * Create many InstituicaoEspiritas and returns the data saved in the database.
     * @param {InstituicaoEspiritaCreateManyAndReturnArgs} args - Arguments to create many InstituicaoEspiritas.
     * @example
     * // Create many InstituicaoEspiritas
     * const instituicaoEspirita = await prisma.instituicaoEspirita.createManyAndReturn({
     *   data: [
     *     // ... provide data here
     *   ]
     * })
     * 
     * // Create many InstituicaoEspiritas and only return the `id`
     * const instituicaoEspiritaWithIdOnly = await prisma.instituicaoEspirita.createManyAndReturn({
     *   select: { id: true },
     *   data: [
     *     // ... provide data here
     *   ]
     * })
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * 
     */
    createManyAndReturn<T extends InstituicaoEspiritaCreateManyAndReturnArgs>(args?: SelectSubset<T, InstituicaoEspiritaCreateManyAndReturnArgs<ExtArgs>>): Prisma.PrismaPromise<$Result.GetResult<Prisma.$InstituicaoEspiritaPayload<ExtArgs>, T, "createManyAndReturn", GlobalOmitOptions>>

    /**
     * Delete a InstituicaoEspirita.
     * @param {InstituicaoEspiritaDeleteArgs} args - Arguments to delete one InstituicaoEspirita.
     * @example
     * // Delete one InstituicaoEspirita
     * const InstituicaoEspirita = await prisma.instituicaoEspirita.delete({
     *   where: {
     *     // ... filter to delete one InstituicaoEspirita
     *   }
     * })
     * 
     */
    delete<T extends InstituicaoEspiritaDeleteArgs>(args: SelectSubset<T, InstituicaoEspiritaDeleteArgs<ExtArgs>>): Prisma__InstituicaoEspiritaClient<$Result.GetResult<Prisma.$InstituicaoEspiritaPayload<ExtArgs>, T, "delete", GlobalOmitOptions>, never, ExtArgs, GlobalOmitOptions>

    /**
     * Update one InstituicaoEspirita.
     * @param {InstituicaoEspiritaUpdateArgs} args - Arguments to update one InstituicaoEspirita.
     * @example
     * // Update one InstituicaoEspirita
     * const instituicaoEspirita = await prisma.instituicaoEspirita.update({
     *   where: {
     *     // ... provide filter here
     *   },
     *   data: {
     *     // ... provide data here
     *   }
     * })
     * 
     */
    update<T extends InstituicaoEspiritaUpdateArgs>(args: SelectSubset<T, InstituicaoEspiritaUpdateArgs<ExtArgs>>): Prisma__InstituicaoEspiritaClient<$Result.GetResult<Prisma.$InstituicaoEspiritaPayload<ExtArgs>, T, "update", GlobalOmitOptions>, never, ExtArgs, GlobalOmitOptions>

    /**
     * Delete zero or more InstituicaoEspiritas.
     * @param {InstituicaoEspiritaDeleteManyArgs} args - Arguments to filter InstituicaoEspiritas to delete.
     * @example
     * // Delete a few InstituicaoEspiritas
     * const { count } = await prisma.instituicaoEspirita.deleteMany({
     *   where: {
     *     // ... provide filter here
     *   }
     * })
     * 
     */
    deleteMany<T extends InstituicaoEspiritaDeleteManyArgs>(args?: SelectSubset<T, InstituicaoEspiritaDeleteManyArgs<ExtArgs>>): Prisma.PrismaPromise<BatchPayload>

    /**
     * Update zero or more InstituicaoEspiritas.
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * @param {InstituicaoEspiritaUpdateManyArgs} args - Arguments to update one or more rows.
     * @example
     * // Update many InstituicaoEspiritas
     * const instituicaoEspirita = await prisma.instituicaoEspirita.updateMany({
     *   where: {
     *     // ... provide filter here
     *   },
     *   data: {
     *     // ... provide data here
     *   }
     * })
     * 
     */
    updateMany<T extends InstituicaoEspiritaUpdateManyArgs>(args: SelectSubset<T, InstituicaoEspiritaUpdateManyArgs<ExtArgs>>): Prisma.PrismaPromise<BatchPayload>

    /**
     * Update zero or more InstituicaoEspiritas and returns the data updated in the database.
     * @param {InstituicaoEspiritaUpdateManyAndReturnArgs} args - Arguments to update many InstituicaoEspiritas.
     * @example
     * // Update many InstituicaoEspiritas
     * const instituicaoEspirita = await prisma.instituicaoEspirita.updateManyAndReturn({
     *   where: {
     *     // ... provide filter here
     *   },
     *   data: [
     *     // ... provide data here
     *   ]
     * })
     * 
     * // Update zero or more InstituicaoEspiritas and only return the `id`
     * const instituicaoEspiritaWithIdOnly = await prisma.instituicaoEspirita.updateManyAndReturn({
     *   select: { id: true },
     *   where: {
     *     // ... provide filter here
     *   },
     *   data: [
     *     // ... provide data here
     *   ]
     * })
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * 
     */
    updateManyAndReturn<T extends InstituicaoEspiritaUpdateManyAndReturnArgs>(args: SelectSubset<T, InstituicaoEspiritaUpdateManyAndReturnArgs<ExtArgs>>): Prisma.PrismaPromise<$Result.GetResult<Prisma.$InstituicaoEspiritaPayload<ExtArgs>, T, "updateManyAndReturn", GlobalOmitOptions>>

    /**
     * Create or update one InstituicaoEspirita.
     * @param {InstituicaoEspiritaUpsertArgs} args - Arguments to update or create a InstituicaoEspirita.
     * @example
     * // Update or create a InstituicaoEspirita
     * const instituicaoEspirita = await prisma.instituicaoEspirita.upsert({
     *   create: {
     *     // ... data to create a InstituicaoEspirita
     *   },
     *   update: {
     *     // ... in case it already exists, update
     *   },
     *   where: {
     *     // ... the filter for the InstituicaoEspirita we want to update
     *   }
     * })
     */
    upsert<T extends InstituicaoEspiritaUpsertArgs>(args: SelectSubset<T, InstituicaoEspiritaUpsertArgs<ExtArgs>>): Prisma__InstituicaoEspiritaClient<$Result.GetResult<Prisma.$InstituicaoEspiritaPayload<ExtArgs>, T, "upsert", GlobalOmitOptions>, never, ExtArgs, GlobalOmitOptions>


    /**
     * Count the number of InstituicaoEspiritas.
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * @param {InstituicaoEspiritaCountArgs} args - Arguments to filter InstituicaoEspiritas to count.
     * @example
     * // Count the number of InstituicaoEspiritas
     * const count = await prisma.instituicaoEspirita.count({
     *   where: {
     *     // ... the filter for the InstituicaoEspiritas we want to count
     *   }
     * })
    **/
    count<T extends InstituicaoEspiritaCountArgs>(
      args?: Subset<T, InstituicaoEspiritaCountArgs>,
    ): Prisma.PrismaPromise<
      T extends $Utils.Record<'select', any>
        ? T['select'] extends true
          ? number
          : GetScalarType<T['select'], InstituicaoEspiritaCountAggregateOutputType>
        : number
    >

    /**
     * Allows you to perform aggregations operations on a InstituicaoEspirita.
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * @param {InstituicaoEspiritaAggregateArgs} args - Select which aggregations you would like to apply and on what fields.
     * @example
     * // Ordered by age ascending
     * // Where email contains prisma.io
     * // Limited to the 10 users
     * const aggregations = await prisma.user.aggregate({
     *   _avg: {
     *     age: true,
     *   },
     *   where: {
     *     email: {
     *       contains: "prisma.io",
     *     },
     *   },
     *   orderBy: {
     *     age: "asc",
     *   },
     *   take: 10,
     * })
    **/
    aggregate<T extends InstituicaoEspiritaAggregateArgs>(args: Subset<T, InstituicaoEspiritaAggregateArgs>): Prisma.PrismaPromise<GetInstituicaoEspiritaAggregateType<T>>

    /**
     * Group by InstituicaoEspirita.
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * @param {InstituicaoEspiritaGroupByArgs} args - Group by arguments.
     * @example
     * // Group by city, order by createdAt, get count
     * const result = await prisma.user.groupBy({
     *   by: ['city', 'createdAt'],
     *   orderBy: {
     *     createdAt: true
     *   },
     *   _count: {
     *     _all: true
     *   },
     * })
     * 
    **/
    groupBy<
      T extends InstituicaoEspiritaGroupByArgs,
      HasSelectOrTake extends Or<
        Extends<'skip', Keys<T>>,
        Extends<'take', Keys<T>>
      >,
      OrderByArg extends True extends HasSelectOrTake
        ? { orderBy: InstituicaoEspiritaGroupByArgs['orderBy'] }
        : { orderBy?: InstituicaoEspiritaGroupByArgs['orderBy'] },
      OrderFields extends ExcludeUnderscoreKeys<Keys<MaybeTupleToUnion<T['orderBy']>>>,
      ByFields extends MaybeTupleToUnion<T['by']>,
      ByValid extends Has<ByFields, OrderFields>,
      HavingFields extends GetHavingFields<T['having']>,
      HavingValid extends Has<ByFields, HavingFields>,
      ByEmpty extends T['by'] extends never[] ? True : False,
      InputErrors extends ByEmpty extends True
      ? `Error: "by" must not be empty.`
      : HavingValid extends False
      ? {
          [P in HavingFields]: P extends ByFields
            ? never
            : P extends string
            ? `Error: Field "${P}" used in "having" needs to be provided in "by".`
            : [
                Error,
                'Field ',
                P,
                ` in "having" needs to be provided in "by"`,
              ]
        }[HavingFields]
      : 'take' extends Keys<T>
      ? 'orderBy' extends Keys<T>
        ? ByValid extends True
          ? {}
          : {
              [P in OrderFields]: P extends ByFields
                ? never
                : `Error: Field "${P}" in "orderBy" needs to be provided in "by"`
            }[OrderFields]
        : 'Error: If you provide "take", you also need to provide "orderBy"'
      : 'skip' extends Keys<T>
      ? 'orderBy' extends Keys<T>
        ? ByValid extends True
          ? {}
          : {
              [P in OrderFields]: P extends ByFields
                ? never
                : `Error: Field "${P}" in "orderBy" needs to be provided in "by"`
            }[OrderFields]
        : 'Error: If you provide "skip", you also need to provide "orderBy"'
      : ByValid extends True
      ? {}
      : {
          [P in OrderFields]: P extends ByFields
            ? never
            : `Error: Field "${P}" in "orderBy" needs to be provided in "by"`
        }[OrderFields]
    >(args: SubsetIntersection<T, InstituicaoEspiritaGroupByArgs, OrderByArg> & InputErrors): {} extends InputErrors ? GetInstituicaoEspiritaGroupByPayload<T> : Prisma.PrismaPromise<InputErrors>
  /**
   * Fields of the InstituicaoEspirita model
   */
  readonly fields: InstituicaoEspiritaFieldRefs;
  }

  /**
   * The delegate class that acts as a "Promise-like" for InstituicaoEspirita.
   * Why is this prefixed with `Prisma__`?
   * Because we want to prevent naming conflicts as mentioned in
   * https://github.com/prisma/prisma-client-js/issues/707
   */
  export interface Prisma__InstituicaoEspiritaClient<T, Null = never, ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs, GlobalOmitOptions = {}> extends Prisma.PrismaPromise<T> {
    readonly [Symbol.toStringTag]: "PrismaPromise"
    atualizadoPor<T extends InstituicaoEspirita$atualizadoPorArgs<ExtArgs> = {}>(args?: Subset<T, InstituicaoEspirita$atualizadoPorArgs<ExtArgs>>): Prisma__UsersClient<$Result.GetResult<Prisma.$UsersPayload<ExtArgs>, T, "findUniqueOrThrow", GlobalOmitOptions> | null, null, ExtArgs, GlobalOmitOptions>
    criadoPor<T extends InstituicaoEspirita$criadoPorArgs<ExtArgs> = {}>(args?: Subset<T, InstituicaoEspirita$criadoPorArgs<ExtArgs>>): Prisma__UsersClient<$Result.GetResult<Prisma.$UsersPayload<ExtArgs>, T, "findUniqueOrThrow", GlobalOmitOptions> | null, null, ExtArgs, GlobalOmitOptions>
    Participante2025<T extends InstituicaoEspirita$Participante2025Args<ExtArgs> = {}>(args?: Subset<T, InstituicaoEspirita$Participante2025Args<ExtArgs>>): Prisma.PrismaPromise<$Result.GetResult<Prisma.$Participante2025Payload<ExtArgs>, T, "findMany", GlobalOmitOptions> | Null>
    Users<T extends InstituicaoEspirita$UsersArgs<ExtArgs> = {}>(args?: Subset<T, InstituicaoEspirita$UsersArgs<ExtArgs>>): Prisma.PrismaPromise<$Result.GetResult<Prisma.$UsersPayload<ExtArgs>, T, "findMany", GlobalOmitOptions> | Null>
    /**
     * Attaches callbacks for the resolution and/or rejection of the Promise.
     * @param onfulfilled The callback to execute when the Promise is resolved.
     * @param onrejected The callback to execute when the Promise is rejected.
     * @returns A Promise for the completion of which ever callback is executed.
     */
    then<TResult1 = T, TResult2 = never>(onfulfilled?: ((value: T) => TResult1 | PromiseLike<TResult1>) | undefined | null, onrejected?: ((reason: any) => TResult2 | PromiseLike<TResult2>) | undefined | null): $Utils.JsPromise<TResult1 | TResult2>
    /**
     * Attaches a callback for only the rejection of the Promise.
     * @param onrejected The callback to execute when the Promise is rejected.
     * @returns A Promise for the completion of the callback.
     */
    catch<TResult = never>(onrejected?: ((reason: any) => TResult | PromiseLike<TResult>) | undefined | null): $Utils.JsPromise<T | TResult>
    /**
     * Attaches a callback that is invoked when the Promise is settled (fulfilled or rejected). The
     * resolved value cannot be modified from the callback.
     * @param onfinally The callback to execute when the Promise is settled (fulfilled or rejected).
     * @returns A Promise for the completion of the callback.
     */
    finally(onfinally?: (() => void) | undefined | null): $Utils.JsPromise<T>
  }




  /**
   * Fields of the InstituicaoEspirita model
   */
  interface InstituicaoEspiritaFieldRefs {
    readonly id: FieldRef<"InstituicaoEspirita", 'Int'>
    readonly nome: FieldRef<"InstituicaoEspirita", 'String'>
    readonly nome_CNPJ: FieldRef<"InstituicaoEspirita", 'String'>
    readonly estado: FieldRef<"InstituicaoEspirita", 'String'>
    readonly cidade: FieldRef<"InstituicaoEspirita", 'String'>
    readonly bairro: FieldRef<"InstituicaoEspirita", 'String'>
    readonly logradouro: FieldRef<"InstituicaoEspirita", 'String'>
    readonly numero: FieldRef<"InstituicaoEspirita", 'String'>
    readonly complemento: FieldRef<"InstituicaoEspirita", 'String'>
    readonly telefone: FieldRef<"InstituicaoEspirita", 'String'>
    readonly email: FieldRef<"InstituicaoEspirita", 'String'>
    readonly createdAt: FieldRef<"InstituicaoEspirita", 'DateTime'>
    readonly updatedAt: FieldRef<"InstituicaoEspirita", 'DateTime'>
    readonly criadoPorId: FieldRef<"InstituicaoEspirita", 'Int'>
    readonly sigla: FieldRef<"InstituicaoEspirita", 'String'>
    readonly CEU: FieldRef<"InstituicaoEspirita", 'String'>
    readonly dia: FieldRef<"InstituicaoEspirita", 'String'>
    readonly horario: FieldRef<"InstituicaoEspirita", 'String'>
    readonly atualizadoPorId: FieldRef<"InstituicaoEspirita", 'Int'>
    readonly CNPJ: FieldRef<"InstituicaoEspirita", 'String'>
  }
    

  // Custom InputTypes
  /**
   * InstituicaoEspirita findUnique
   */
  export type InstituicaoEspiritaFindUniqueArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the InstituicaoEspirita
     */
    select?: InstituicaoEspiritaSelect<ExtArgs> | null
    /**
     * Omit specific fields from the InstituicaoEspirita
     */
    omit?: InstituicaoEspiritaOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: InstituicaoEspiritaInclude<ExtArgs> | null
    /**
     * Filter, which InstituicaoEspirita to fetch.
     */
    where: InstituicaoEspiritaWhereUniqueInput
  }

  /**
   * InstituicaoEspirita findUniqueOrThrow
   */
  export type InstituicaoEspiritaFindUniqueOrThrowArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the InstituicaoEspirita
     */
    select?: InstituicaoEspiritaSelect<ExtArgs> | null
    /**
     * Omit specific fields from the InstituicaoEspirita
     */
    omit?: InstituicaoEspiritaOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: InstituicaoEspiritaInclude<ExtArgs> | null
    /**
     * Filter, which InstituicaoEspirita to fetch.
     */
    where: InstituicaoEspiritaWhereUniqueInput
  }

  /**
   * InstituicaoEspirita findFirst
   */
  export type InstituicaoEspiritaFindFirstArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the InstituicaoEspirita
     */
    select?: InstituicaoEspiritaSelect<ExtArgs> | null
    /**
     * Omit specific fields from the InstituicaoEspirita
     */
    omit?: InstituicaoEspiritaOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: InstituicaoEspiritaInclude<ExtArgs> | null
    /**
     * Filter, which InstituicaoEspirita to fetch.
     */
    where?: InstituicaoEspiritaWhereInput
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/sorting Sorting Docs}
     * 
     * Determine the order of InstituicaoEspiritas to fetch.
     */
    orderBy?: InstituicaoEspiritaOrderByWithRelationInput | InstituicaoEspiritaOrderByWithRelationInput[]
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination#cursor-based-pagination Cursor Docs}
     * 
     * Sets the position for searching for InstituicaoEspiritas.
     */
    cursor?: InstituicaoEspiritaWhereUniqueInput
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination Pagination Docs}
     * 
     * Take `±n` InstituicaoEspiritas from the position of the cursor.
     */
    take?: number
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination Pagination Docs}
     * 
     * Skip the first `n` InstituicaoEspiritas.
     */
    skip?: number
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/distinct Distinct Docs}
     * 
     * Filter by unique combinations of InstituicaoEspiritas.
     */
    distinct?: InstituicaoEspiritaScalarFieldEnum | InstituicaoEspiritaScalarFieldEnum[]
  }

  /**
   * InstituicaoEspirita findFirstOrThrow
   */
  export type InstituicaoEspiritaFindFirstOrThrowArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the InstituicaoEspirita
     */
    select?: InstituicaoEspiritaSelect<ExtArgs> | null
    /**
     * Omit specific fields from the InstituicaoEspirita
     */
    omit?: InstituicaoEspiritaOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: InstituicaoEspiritaInclude<ExtArgs> | null
    /**
     * Filter, which InstituicaoEspirita to fetch.
     */
    where?: InstituicaoEspiritaWhereInput
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/sorting Sorting Docs}
     * 
     * Determine the order of InstituicaoEspiritas to fetch.
     */
    orderBy?: InstituicaoEspiritaOrderByWithRelationInput | InstituicaoEspiritaOrderByWithRelationInput[]
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination#cursor-based-pagination Cursor Docs}
     * 
     * Sets the position for searching for InstituicaoEspiritas.
     */
    cursor?: InstituicaoEspiritaWhereUniqueInput
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination Pagination Docs}
     * 
     * Take `±n` InstituicaoEspiritas from the position of the cursor.
     */
    take?: number
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination Pagination Docs}
     * 
     * Skip the first `n` InstituicaoEspiritas.
     */
    skip?: number
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/distinct Distinct Docs}
     * 
     * Filter by unique combinations of InstituicaoEspiritas.
     */
    distinct?: InstituicaoEspiritaScalarFieldEnum | InstituicaoEspiritaScalarFieldEnum[]
  }

  /**
   * InstituicaoEspirita findMany
   */
  export type InstituicaoEspiritaFindManyArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the InstituicaoEspirita
     */
    select?: InstituicaoEspiritaSelect<ExtArgs> | null
    /**
     * Omit specific fields from the InstituicaoEspirita
     */
    omit?: InstituicaoEspiritaOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: InstituicaoEspiritaInclude<ExtArgs> | null
    /**
     * Filter, which InstituicaoEspiritas to fetch.
     */
    where?: InstituicaoEspiritaWhereInput
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/sorting Sorting Docs}
     * 
     * Determine the order of InstituicaoEspiritas to fetch.
     */
    orderBy?: InstituicaoEspiritaOrderByWithRelationInput | InstituicaoEspiritaOrderByWithRelationInput[]
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination#cursor-based-pagination Cursor Docs}
     * 
     * Sets the position for listing InstituicaoEspiritas.
     */
    cursor?: InstituicaoEspiritaWhereUniqueInput
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination Pagination Docs}
     * 
     * Take `±n` InstituicaoEspiritas from the position of the cursor.
     */
    take?: number
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination Pagination Docs}
     * 
     * Skip the first `n` InstituicaoEspiritas.
     */
    skip?: number
    distinct?: InstituicaoEspiritaScalarFieldEnum | InstituicaoEspiritaScalarFieldEnum[]
  }

  /**
   * InstituicaoEspirita create
   */
  export type InstituicaoEspiritaCreateArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the InstituicaoEspirita
     */
    select?: InstituicaoEspiritaSelect<ExtArgs> | null
    /**
     * Omit specific fields from the InstituicaoEspirita
     */
    omit?: InstituicaoEspiritaOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: InstituicaoEspiritaInclude<ExtArgs> | null
    /**
     * The data needed to create a InstituicaoEspirita.
     */
    data: XOR<InstituicaoEspiritaCreateInput, InstituicaoEspiritaUncheckedCreateInput>
  }

  /**
   * InstituicaoEspirita createMany
   */
  export type InstituicaoEspiritaCreateManyArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * The data used to create many InstituicaoEspiritas.
     */
    data: InstituicaoEspiritaCreateManyInput | InstituicaoEspiritaCreateManyInput[]
    skipDuplicates?: boolean
  }

  /**
   * InstituicaoEspirita createManyAndReturn
   */
  export type InstituicaoEspiritaCreateManyAndReturnArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the InstituicaoEspirita
     */
    select?: InstituicaoEspiritaSelectCreateManyAndReturn<ExtArgs> | null
    /**
     * Omit specific fields from the InstituicaoEspirita
     */
    omit?: InstituicaoEspiritaOmit<ExtArgs> | null
    /**
     * The data used to create many InstituicaoEspiritas.
     */
    data: InstituicaoEspiritaCreateManyInput | InstituicaoEspiritaCreateManyInput[]
    skipDuplicates?: boolean
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: InstituicaoEspiritaIncludeCreateManyAndReturn<ExtArgs> | null
  }

  /**
   * InstituicaoEspirita update
   */
  export type InstituicaoEspiritaUpdateArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the InstituicaoEspirita
     */
    select?: InstituicaoEspiritaSelect<ExtArgs> | null
    /**
     * Omit specific fields from the InstituicaoEspirita
     */
    omit?: InstituicaoEspiritaOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: InstituicaoEspiritaInclude<ExtArgs> | null
    /**
     * The data needed to update a InstituicaoEspirita.
     */
    data: XOR<InstituicaoEspiritaUpdateInput, InstituicaoEspiritaUncheckedUpdateInput>
    /**
     * Choose, which InstituicaoEspirita to update.
     */
    where: InstituicaoEspiritaWhereUniqueInput
  }

  /**
   * InstituicaoEspirita updateMany
   */
  export type InstituicaoEspiritaUpdateManyArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * The data used to update InstituicaoEspiritas.
     */
    data: XOR<InstituicaoEspiritaUpdateManyMutationInput, InstituicaoEspiritaUncheckedUpdateManyInput>
    /**
     * Filter which InstituicaoEspiritas to update
     */
    where?: InstituicaoEspiritaWhereInput
    /**
     * Limit how many InstituicaoEspiritas to update.
     */
    limit?: number
  }

  /**
   * InstituicaoEspirita updateManyAndReturn
   */
  export type InstituicaoEspiritaUpdateManyAndReturnArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the InstituicaoEspirita
     */
    select?: InstituicaoEspiritaSelectUpdateManyAndReturn<ExtArgs> | null
    /**
     * Omit specific fields from the InstituicaoEspirita
     */
    omit?: InstituicaoEspiritaOmit<ExtArgs> | null
    /**
     * The data used to update InstituicaoEspiritas.
     */
    data: XOR<InstituicaoEspiritaUpdateManyMutationInput, InstituicaoEspiritaUncheckedUpdateManyInput>
    /**
     * Filter which InstituicaoEspiritas to update
     */
    where?: InstituicaoEspiritaWhereInput
    /**
     * Limit how many InstituicaoEspiritas to update.
     */
    limit?: number
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: InstituicaoEspiritaIncludeUpdateManyAndReturn<ExtArgs> | null
  }

  /**
   * InstituicaoEspirita upsert
   */
  export type InstituicaoEspiritaUpsertArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the InstituicaoEspirita
     */
    select?: InstituicaoEspiritaSelect<ExtArgs> | null
    /**
     * Omit specific fields from the InstituicaoEspirita
     */
    omit?: InstituicaoEspiritaOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: InstituicaoEspiritaInclude<ExtArgs> | null
    /**
     * The filter to search for the InstituicaoEspirita to update in case it exists.
     */
    where: InstituicaoEspiritaWhereUniqueInput
    /**
     * In case the InstituicaoEspirita found by the `where` argument doesn't exist, create a new InstituicaoEspirita with this data.
     */
    create: XOR<InstituicaoEspiritaCreateInput, InstituicaoEspiritaUncheckedCreateInput>
    /**
     * In case the InstituicaoEspirita was found with the provided `where` argument, update it with this data.
     */
    update: XOR<InstituicaoEspiritaUpdateInput, InstituicaoEspiritaUncheckedUpdateInput>
  }

  /**
   * InstituicaoEspirita delete
   */
  export type InstituicaoEspiritaDeleteArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the InstituicaoEspirita
     */
    select?: InstituicaoEspiritaSelect<ExtArgs> | null
    /**
     * Omit specific fields from the InstituicaoEspirita
     */
    omit?: InstituicaoEspiritaOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: InstituicaoEspiritaInclude<ExtArgs> | null
    /**
     * Filter which InstituicaoEspirita to delete.
     */
    where: InstituicaoEspiritaWhereUniqueInput
  }

  /**
   * InstituicaoEspirita deleteMany
   */
  export type InstituicaoEspiritaDeleteManyArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Filter which InstituicaoEspiritas to delete
     */
    where?: InstituicaoEspiritaWhereInput
    /**
     * Limit how many InstituicaoEspiritas to delete.
     */
    limit?: number
  }

  /**
   * InstituicaoEspirita.atualizadoPor
   */
  export type InstituicaoEspirita$atualizadoPorArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the Users
     */
    select?: UsersSelect<ExtArgs> | null
    /**
     * Omit specific fields from the Users
     */
    omit?: UsersOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: UsersInclude<ExtArgs> | null
    where?: UsersWhereInput
  }

  /**
   * InstituicaoEspirita.criadoPor
   */
  export type InstituicaoEspirita$criadoPorArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the Users
     */
    select?: UsersSelect<ExtArgs> | null
    /**
     * Omit specific fields from the Users
     */
    omit?: UsersOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: UsersInclude<ExtArgs> | null
    where?: UsersWhereInput
  }

  /**
   * InstituicaoEspirita.Participante2025
   */
  export type InstituicaoEspirita$Participante2025Args<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the Participante2025
     */
    select?: Participante2025Select<ExtArgs> | null
    /**
     * Omit specific fields from the Participante2025
     */
    omit?: Participante2025Omit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: Participante2025Include<ExtArgs> | null
    where?: Participante2025WhereInput
    orderBy?: Participante2025OrderByWithRelationInput | Participante2025OrderByWithRelationInput[]
    cursor?: Participante2025WhereUniqueInput
    take?: number
    skip?: number
    distinct?: Participante2025ScalarFieldEnum | Participante2025ScalarFieldEnum[]
  }

  /**
   * InstituicaoEspirita.Users
   */
  export type InstituicaoEspirita$UsersArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the Users
     */
    select?: UsersSelect<ExtArgs> | null
    /**
     * Omit specific fields from the Users
     */
    omit?: UsersOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: UsersInclude<ExtArgs> | null
    where?: UsersWhereInput
    orderBy?: UsersOrderByWithRelationInput | UsersOrderByWithRelationInput[]
    cursor?: UsersWhereUniqueInput
    take?: number
    skip?: number
    distinct?: UsersScalarFieldEnum | UsersScalarFieldEnum[]
  }

  /**
   * InstituicaoEspirita without action
   */
  export type InstituicaoEspiritaDefaultArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the InstituicaoEspirita
     */
    select?: InstituicaoEspiritaSelect<ExtArgs> | null
    /**
     * Omit specific fields from the InstituicaoEspirita
     */
    omit?: InstituicaoEspiritaOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: InstituicaoEspiritaInclude<ExtArgs> | null
  }


  /**
   * Model Participante2025
   */

  export type AggregateParticipante2025 = {
    _count: Participante2025CountAggregateOutputType | null
    _avg: Participante2025AvgAggregateOutputType | null
    _sum: Participante2025SumAggregateOutputType | null
    _min: Participante2025MinAggregateOutputType | null
    _max: Participante2025MaxAggregateOutputType | null
  }

  export type Participante2025AvgAggregateOutputType = {
    idade: number | null
    valor: number | null
    userId: number | null
    instituicaoId: number | null
  }

  export type Participante2025SumAggregateOutputType = {
    idade: number | null
    valor: number | null
    userId: number | null
    instituicaoId: number | null
  }

  export type Participante2025MinAggregateOutputType = {
    id: string | null
    nomeCompleto: string | null
    nomeCracha: string | null
    cpf: string | null
    nomeSocial: string | null
    dataNascimento: Date | null
    sexo: string | null
    email: string | null
    telefone: string | null
    nomeCompletoResponsavel: string | null
    documentoResponsavel: string | null
    telefoneResponsavel: string | null
    linkPagamento: string | null
    idade: number | null
    valor: number | null
    statusPagamento: string | null
    tipoParticipacao: $Enums.TipoParticipacao | null
    comissao: string | null
    tamanhoCamisa: string | null
    cep: string | null
    estado: string | null
    cidade: string | null
    bairro: string | null
    logradouro: string | null
    numero: string | null
    complemento: string | null
    outroGenero: string | null
    medicacao: string | null
    alergia: string | null
    outrasInformacoes: string | null
    userId: number | null
    createdAt: Date | null
    updatedAt: Date | null
    IE: string | null
    instituicaoId: number | null
    vegetariano: string | null
    camisa: boolean | null
    primeiraComejaca: boolean | null
    deficienciaAuditiva: boolean | null
    deficienciaAutismo: boolean | null
    deficienciaIntelectual: boolean | null
    deficienciaParalisiaCerebral: boolean | null
    deficienciaVisual: boolean | null
    deficienciaFisica: boolean | null
    deficienciaOutra: boolean | null
    deficienciaOutraDescricao: string | null
    otherInstitution: string | null
  }

  export type Participante2025MaxAggregateOutputType = {
    id: string | null
    nomeCompleto: string | null
    nomeCracha: string | null
    cpf: string | null
    nomeSocial: string | null
    dataNascimento: Date | null
    sexo: string | null
    email: string | null
    telefone: string | null
    nomeCompletoResponsavel: string | null
    documentoResponsavel: string | null
    telefoneResponsavel: string | null
    linkPagamento: string | null
    idade: number | null
    valor: number | null
    statusPagamento: string | null
    tipoParticipacao: $Enums.TipoParticipacao | null
    comissao: string | null
    tamanhoCamisa: string | null
    cep: string | null
    estado: string | null
    cidade: string | null
    bairro: string | null
    logradouro: string | null
    numero: string | null
    complemento: string | null
    outroGenero: string | null
    medicacao: string | null
    alergia: string | null
    outrasInformacoes: string | null
    userId: number | null
    createdAt: Date | null
    updatedAt: Date | null
    IE: string | null
    instituicaoId: number | null
    vegetariano: string | null
    camisa: boolean | null
    primeiraComejaca: boolean | null
    deficienciaAuditiva: boolean | null
    deficienciaAutismo: boolean | null
    deficienciaIntelectual: boolean | null
    deficienciaParalisiaCerebral: boolean | null
    deficienciaVisual: boolean | null
    deficienciaFisica: boolean | null
    deficienciaOutra: boolean | null
    deficienciaOutraDescricao: string | null
    otherInstitution: string | null
  }

  export type Participante2025CountAggregateOutputType = {
    id: number
    nomeCompleto: number
    nomeCracha: number
    cpf: number
    nomeSocial: number
    dataNascimento: number
    sexo: number
    email: number
    telefone: number
    nomeCompletoResponsavel: number
    documentoResponsavel: number
    telefoneResponsavel: number
    linkPagamento: number
    idade: number
    valor: number
    statusPagamento: number
    tipoParticipacao: number
    comissao: number
    tamanhoCamisa: number
    cep: number
    estado: number
    cidade: number
    bairro: number
    logradouro: number
    numero: number
    complemento: number
    outroGenero: number
    medicacao: number
    alergia: number
    outrasInformacoes: number
    userId: number
    createdAt: number
    updatedAt: number
    IE: number
    instituicaoId: number
    vegetariano: number
    camisa: number
    primeiraComejaca: number
    deficienciaAuditiva: number
    deficienciaAutismo: number
    deficienciaIntelectual: number
    deficienciaParalisiaCerebral: number
    deficienciaVisual: number
    deficienciaFisica: number
    deficienciaOutra: number
    deficienciaOutraDescricao: number
    otherInstitution: number
    _all: number
  }


  export type Participante2025AvgAggregateInputType = {
    idade?: true
    valor?: true
    userId?: true
    instituicaoId?: true
  }

  export type Participante2025SumAggregateInputType = {
    idade?: true
    valor?: true
    userId?: true
    instituicaoId?: true
  }

  export type Participante2025MinAggregateInputType = {
    id?: true
    nomeCompleto?: true
    nomeCracha?: true
    cpf?: true
    nomeSocial?: true
    dataNascimento?: true
    sexo?: true
    email?: true
    telefone?: true
    nomeCompletoResponsavel?: true
    documentoResponsavel?: true
    telefoneResponsavel?: true
    linkPagamento?: true
    idade?: true
    valor?: true
    statusPagamento?: true
    tipoParticipacao?: true
    comissao?: true
    tamanhoCamisa?: true
    cep?: true
    estado?: true
    cidade?: true
    bairro?: true
    logradouro?: true
    numero?: true
    complemento?: true
    outroGenero?: true
    medicacao?: true
    alergia?: true
    outrasInformacoes?: true
    userId?: true
    createdAt?: true
    updatedAt?: true
    IE?: true
    instituicaoId?: true
    vegetariano?: true
    camisa?: true
    primeiraComejaca?: true
    deficienciaAuditiva?: true
    deficienciaAutismo?: true
    deficienciaIntelectual?: true
    deficienciaParalisiaCerebral?: true
    deficienciaVisual?: true
    deficienciaFisica?: true
    deficienciaOutra?: true
    deficienciaOutraDescricao?: true
    otherInstitution?: true
  }

  export type Participante2025MaxAggregateInputType = {
    id?: true
    nomeCompleto?: true
    nomeCracha?: true
    cpf?: true
    nomeSocial?: true
    dataNascimento?: true
    sexo?: true
    email?: true
    telefone?: true
    nomeCompletoResponsavel?: true
    documentoResponsavel?: true
    telefoneResponsavel?: true
    linkPagamento?: true
    idade?: true
    valor?: true
    statusPagamento?: true
    tipoParticipacao?: true
    comissao?: true
    tamanhoCamisa?: true
    cep?: true
    estado?: true
    cidade?: true
    bairro?: true
    logradouro?: true
    numero?: true
    complemento?: true
    outroGenero?: true
    medicacao?: true
    alergia?: true
    outrasInformacoes?: true
    userId?: true
    createdAt?: true
    updatedAt?: true
    IE?: true
    instituicaoId?: true
    vegetariano?: true
    camisa?: true
    primeiraComejaca?: true
    deficienciaAuditiva?: true
    deficienciaAutismo?: true
    deficienciaIntelectual?: true
    deficienciaParalisiaCerebral?: true
    deficienciaVisual?: true
    deficienciaFisica?: true
    deficienciaOutra?: true
    deficienciaOutraDescricao?: true
    otherInstitution?: true
  }

  export type Participante2025CountAggregateInputType = {
    id?: true
    nomeCompleto?: true
    nomeCracha?: true
    cpf?: true
    nomeSocial?: true
    dataNascimento?: true
    sexo?: true
    email?: true
    telefone?: true
    nomeCompletoResponsavel?: true
    documentoResponsavel?: true
    telefoneResponsavel?: true
    linkPagamento?: true
    idade?: true
    valor?: true
    statusPagamento?: true
    tipoParticipacao?: true
    comissao?: true
    tamanhoCamisa?: true
    cep?: true
    estado?: true
    cidade?: true
    bairro?: true
    logradouro?: true
    numero?: true
    complemento?: true
    outroGenero?: true
    medicacao?: true
    alergia?: true
    outrasInformacoes?: true
    userId?: true
    createdAt?: true
    updatedAt?: true
    IE?: true
    instituicaoId?: true
    vegetariano?: true
    camisa?: true
    primeiraComejaca?: true
    deficienciaAuditiva?: true
    deficienciaAutismo?: true
    deficienciaIntelectual?: true
    deficienciaParalisiaCerebral?: true
    deficienciaVisual?: true
    deficienciaFisica?: true
    deficienciaOutra?: true
    deficienciaOutraDescricao?: true
    otherInstitution?: true
    _all?: true
  }

  export type Participante2025AggregateArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Filter which Participante2025 to aggregate.
     */
    where?: Participante2025WhereInput
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/sorting Sorting Docs}
     * 
     * Determine the order of Participante2025s to fetch.
     */
    orderBy?: Participante2025OrderByWithRelationInput | Participante2025OrderByWithRelationInput[]
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination#cursor-based-pagination Cursor Docs}
     * 
     * Sets the start position
     */
    cursor?: Participante2025WhereUniqueInput
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination Pagination Docs}
     * 
     * Take `±n` Participante2025s from the position of the cursor.
     */
    take?: number
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination Pagination Docs}
     * 
     * Skip the first `n` Participante2025s.
     */
    skip?: number
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/aggregations Aggregation Docs}
     * 
     * Count returned Participante2025s
    **/
    _count?: true | Participante2025CountAggregateInputType
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/aggregations Aggregation Docs}
     * 
     * Select which fields to average
    **/
    _avg?: Participante2025AvgAggregateInputType
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/aggregations Aggregation Docs}
     * 
     * Select which fields to sum
    **/
    _sum?: Participante2025SumAggregateInputType
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/aggregations Aggregation Docs}
     * 
     * Select which fields to find the minimum value
    **/
    _min?: Participante2025MinAggregateInputType
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/aggregations Aggregation Docs}
     * 
     * Select which fields to find the maximum value
    **/
    _max?: Participante2025MaxAggregateInputType
  }

  export type GetParticipante2025AggregateType<T extends Participante2025AggregateArgs> = {
        [P in keyof T & keyof AggregateParticipante2025]: P extends '_count' | 'count'
      ? T[P] extends true
        ? number
        : GetScalarType<T[P], AggregateParticipante2025[P]>
      : GetScalarType<T[P], AggregateParticipante2025[P]>
  }




  export type Participante2025GroupByArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    where?: Participante2025WhereInput
    orderBy?: Participante2025OrderByWithAggregationInput | Participante2025OrderByWithAggregationInput[]
    by: Participante2025ScalarFieldEnum[] | Participante2025ScalarFieldEnum
    having?: Participante2025ScalarWhereWithAggregatesInput
    take?: number
    skip?: number
    _count?: Participante2025CountAggregateInputType | true
    _avg?: Participante2025AvgAggregateInputType
    _sum?: Participante2025SumAggregateInputType
    _min?: Participante2025MinAggregateInputType
    _max?: Participante2025MaxAggregateInputType
  }

  export type Participante2025GroupByOutputType = {
    id: string
    nomeCompleto: string
    nomeCracha: string | null
    cpf: string | null
    nomeSocial: string | null
    dataNascimento: Date
    sexo: string
    email: string
    telefone: string
    nomeCompletoResponsavel: string | null
    documentoResponsavel: string | null
    telefoneResponsavel: string | null
    linkPagamento: string | null
    idade: number | null
    valor: number | null
    statusPagamento: string | null
    tipoParticipacao: $Enums.TipoParticipacao
    comissao: string | null
    tamanhoCamisa: string | null
    cep: string
    estado: string | null
    cidade: string | null
    bairro: string | null
    logradouro: string | null
    numero: string | null
    complemento: string | null
    outroGenero: string | null
    medicacao: string | null
    alergia: string | null
    outrasInformacoes: string | null
    userId: number | null
    createdAt: Date
    updatedAt: Date
    IE: string
    instituicaoId: number | null
    vegetariano: string
    camisa: boolean | null
    primeiraComejaca: boolean | null
    deficienciaAuditiva: boolean | null
    deficienciaAutismo: boolean | null
    deficienciaIntelectual: boolean | null
    deficienciaParalisiaCerebral: boolean | null
    deficienciaVisual: boolean | null
    deficienciaFisica: boolean | null
    deficienciaOutra: boolean | null
    deficienciaOutraDescricao: string | null
    otherInstitution: string | null
    _count: Participante2025CountAggregateOutputType | null
    _avg: Participante2025AvgAggregateOutputType | null
    _sum: Participante2025SumAggregateOutputType | null
    _min: Participante2025MinAggregateOutputType | null
    _max: Participante2025MaxAggregateOutputType | null
  }

  type GetParticipante2025GroupByPayload<T extends Participante2025GroupByArgs> = Prisma.PrismaPromise<
    Array<
      PickEnumerable<Participante2025GroupByOutputType, T['by']> &
        {
          [P in ((keyof T) & (keyof Participante2025GroupByOutputType))]: P extends '_count'
            ? T[P] extends boolean
              ? number
              : GetScalarType<T[P], Participante2025GroupByOutputType[P]>
            : GetScalarType<T[P], Participante2025GroupByOutputType[P]>
        }
      >
    >


  export type Participante2025Select<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = $Extensions.GetSelect<{
    id?: boolean
    nomeCompleto?: boolean
    nomeCracha?: boolean
    cpf?: boolean
    nomeSocial?: boolean
    dataNascimento?: boolean
    sexo?: boolean
    email?: boolean
    telefone?: boolean
    nomeCompletoResponsavel?: boolean
    documentoResponsavel?: boolean
    telefoneResponsavel?: boolean
    linkPagamento?: boolean
    idade?: boolean
    valor?: boolean
    statusPagamento?: boolean
    tipoParticipacao?: boolean
    comissao?: boolean
    tamanhoCamisa?: boolean
    cep?: boolean
    estado?: boolean
    cidade?: boolean
    bairro?: boolean
    logradouro?: boolean
    numero?: boolean
    complemento?: boolean
    outroGenero?: boolean
    medicacao?: boolean
    alergia?: boolean
    outrasInformacoes?: boolean
    userId?: boolean
    createdAt?: boolean
    updatedAt?: boolean
    IE?: boolean
    instituicaoId?: boolean
    vegetariano?: boolean
    camisa?: boolean
    primeiraComejaca?: boolean
    deficienciaAuditiva?: boolean
    deficienciaAutismo?: boolean
    deficienciaIntelectual?: boolean
    deficienciaParalisiaCerebral?: boolean
    deficienciaVisual?: boolean
    deficienciaFisica?: boolean
    deficienciaOutra?: boolean
    deficienciaOutraDescricao?: boolean
    otherInstitution?: boolean
    instituicao?: boolean | Participante2025$instituicaoArgs<ExtArgs>
    user?: boolean | Participante2025$userArgs<ExtArgs>
  }, ExtArgs["result"]["participante2025"]>

  export type Participante2025SelectCreateManyAndReturn<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = $Extensions.GetSelect<{
    id?: boolean
    nomeCompleto?: boolean
    nomeCracha?: boolean
    cpf?: boolean
    nomeSocial?: boolean
    dataNascimento?: boolean
    sexo?: boolean
    email?: boolean
    telefone?: boolean
    nomeCompletoResponsavel?: boolean
    documentoResponsavel?: boolean
    telefoneResponsavel?: boolean
    linkPagamento?: boolean
    idade?: boolean
    valor?: boolean
    statusPagamento?: boolean
    tipoParticipacao?: boolean
    comissao?: boolean
    tamanhoCamisa?: boolean
    cep?: boolean
    estado?: boolean
    cidade?: boolean
    bairro?: boolean
    logradouro?: boolean
    numero?: boolean
    complemento?: boolean
    outroGenero?: boolean
    medicacao?: boolean
    alergia?: boolean
    outrasInformacoes?: boolean
    userId?: boolean
    createdAt?: boolean
    updatedAt?: boolean
    IE?: boolean
    instituicaoId?: boolean
    vegetariano?: boolean
    camisa?: boolean
    primeiraComejaca?: boolean
    deficienciaAuditiva?: boolean
    deficienciaAutismo?: boolean
    deficienciaIntelectual?: boolean
    deficienciaParalisiaCerebral?: boolean
    deficienciaVisual?: boolean
    deficienciaFisica?: boolean
    deficienciaOutra?: boolean
    deficienciaOutraDescricao?: boolean
    otherInstitution?: boolean
    instituicao?: boolean | Participante2025$instituicaoArgs<ExtArgs>
    user?: boolean | Participante2025$userArgs<ExtArgs>
  }, ExtArgs["result"]["participante2025"]>

  export type Participante2025SelectUpdateManyAndReturn<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = $Extensions.GetSelect<{
    id?: boolean
    nomeCompleto?: boolean
    nomeCracha?: boolean
    cpf?: boolean
    nomeSocial?: boolean
    dataNascimento?: boolean
    sexo?: boolean
    email?: boolean
    telefone?: boolean
    nomeCompletoResponsavel?: boolean
    documentoResponsavel?: boolean
    telefoneResponsavel?: boolean
    linkPagamento?: boolean
    idade?: boolean
    valor?: boolean
    statusPagamento?: boolean
    tipoParticipacao?: boolean
    comissao?: boolean
    tamanhoCamisa?: boolean
    cep?: boolean
    estado?: boolean
    cidade?: boolean
    bairro?: boolean
    logradouro?: boolean
    numero?: boolean
    complemento?: boolean
    outroGenero?: boolean
    medicacao?: boolean
    alergia?: boolean
    outrasInformacoes?: boolean
    userId?: boolean
    createdAt?: boolean
    updatedAt?: boolean
    IE?: boolean
    instituicaoId?: boolean
    vegetariano?: boolean
    camisa?: boolean
    primeiraComejaca?: boolean
    deficienciaAuditiva?: boolean
    deficienciaAutismo?: boolean
    deficienciaIntelectual?: boolean
    deficienciaParalisiaCerebral?: boolean
    deficienciaVisual?: boolean
    deficienciaFisica?: boolean
    deficienciaOutra?: boolean
    deficienciaOutraDescricao?: boolean
    otherInstitution?: boolean
    instituicao?: boolean | Participante2025$instituicaoArgs<ExtArgs>
    user?: boolean | Participante2025$userArgs<ExtArgs>
  }, ExtArgs["result"]["participante2025"]>

  export type Participante2025SelectScalar = {
    id?: boolean
    nomeCompleto?: boolean
    nomeCracha?: boolean
    cpf?: boolean
    nomeSocial?: boolean
    dataNascimento?: boolean
    sexo?: boolean
    email?: boolean
    telefone?: boolean
    nomeCompletoResponsavel?: boolean
    documentoResponsavel?: boolean
    telefoneResponsavel?: boolean
    linkPagamento?: boolean
    idade?: boolean
    valor?: boolean
    statusPagamento?: boolean
    tipoParticipacao?: boolean
    comissao?: boolean
    tamanhoCamisa?: boolean
    cep?: boolean
    estado?: boolean
    cidade?: boolean
    bairro?: boolean
    logradouro?: boolean
    numero?: boolean
    complemento?: boolean
    outroGenero?: boolean
    medicacao?: boolean
    alergia?: boolean
    outrasInformacoes?: boolean
    userId?: boolean
    createdAt?: boolean
    updatedAt?: boolean
    IE?: boolean
    instituicaoId?: boolean
    vegetariano?: boolean
    camisa?: boolean
    primeiraComejaca?: boolean
    deficienciaAuditiva?: boolean
    deficienciaAutismo?: boolean
    deficienciaIntelectual?: boolean
    deficienciaParalisiaCerebral?: boolean
    deficienciaVisual?: boolean
    deficienciaFisica?: boolean
    deficienciaOutra?: boolean
    deficienciaOutraDescricao?: boolean
    otherInstitution?: boolean
  }

  export type Participante2025Omit<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = $Extensions.GetOmit<"id" | "nomeCompleto" | "nomeCracha" | "cpf" | "nomeSocial" | "dataNascimento" | "sexo" | "email" | "telefone" | "nomeCompletoResponsavel" | "documentoResponsavel" | "telefoneResponsavel" | "linkPagamento" | "idade" | "valor" | "statusPagamento" | "tipoParticipacao" | "comissao" | "tamanhoCamisa" | "cep" | "estado" | "cidade" | "bairro" | "logradouro" | "numero" | "complemento" | "outroGenero" | "medicacao" | "alergia" | "outrasInformacoes" | "userId" | "createdAt" | "updatedAt" | "IE" | "instituicaoId" | "vegetariano" | "camisa" | "primeiraComejaca" | "deficienciaAuditiva" | "deficienciaAutismo" | "deficienciaIntelectual" | "deficienciaParalisiaCerebral" | "deficienciaVisual" | "deficienciaFisica" | "deficienciaOutra" | "deficienciaOutraDescricao" | "otherInstitution", ExtArgs["result"]["participante2025"]>
  export type Participante2025Include<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    instituicao?: boolean | Participante2025$instituicaoArgs<ExtArgs>
    user?: boolean | Participante2025$userArgs<ExtArgs>
  }
  export type Participante2025IncludeCreateManyAndReturn<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    instituicao?: boolean | Participante2025$instituicaoArgs<ExtArgs>
    user?: boolean | Participante2025$userArgs<ExtArgs>
  }
  export type Participante2025IncludeUpdateManyAndReturn<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    instituicao?: boolean | Participante2025$instituicaoArgs<ExtArgs>
    user?: boolean | Participante2025$userArgs<ExtArgs>
  }

  export type $Participante2025Payload<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    name: "Participante2025"
    objects: {
      instituicao: Prisma.$InstituicaoEspiritaPayload<ExtArgs> | null
      user: Prisma.$UsersPayload<ExtArgs> | null
    }
    scalars: $Extensions.GetPayloadResult<{
      id: string
      nomeCompleto: string
      nomeCracha: string | null
      cpf: string | null
      nomeSocial: string | null
      dataNascimento: Date
      sexo: string
      email: string
      telefone: string
      nomeCompletoResponsavel: string | null
      documentoResponsavel: string | null
      telefoneResponsavel: string | null
      linkPagamento: string | null
      idade: number | null
      valor: number | null
      statusPagamento: string | null
      tipoParticipacao: $Enums.TipoParticipacao
      comissao: string | null
      tamanhoCamisa: string | null
      cep: string
      estado: string | null
      cidade: string | null
      bairro: string | null
      logradouro: string | null
      numero: string | null
      complemento: string | null
      outroGenero: string | null
      medicacao: string | null
      alergia: string | null
      outrasInformacoes: string | null
      userId: number | null
      createdAt: Date
      updatedAt: Date
      IE: string
      instituicaoId: number | null
      vegetariano: string
      camisa: boolean | null
      primeiraComejaca: boolean | null
      deficienciaAuditiva: boolean | null
      deficienciaAutismo: boolean | null
      deficienciaIntelectual: boolean | null
      deficienciaParalisiaCerebral: boolean | null
      deficienciaVisual: boolean | null
      deficienciaFisica: boolean | null
      deficienciaOutra: boolean | null
      deficienciaOutraDescricao: string | null
      otherInstitution: string | null
    }, ExtArgs["result"]["participante2025"]>
    composites: {}
  }

  type Participante2025GetPayload<S extends boolean | null | undefined | Participante2025DefaultArgs> = $Result.GetResult<Prisma.$Participante2025Payload, S>

  type Participante2025CountArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> =
    Omit<Participante2025FindManyArgs, 'select' | 'include' | 'distinct' | 'omit'> & {
      select?: Participante2025CountAggregateInputType | true
    }

  export interface Participante2025Delegate<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs, GlobalOmitOptions = {}> {
    [K: symbol]: { types: Prisma.TypeMap<ExtArgs>['model']['Participante2025'], meta: { name: 'Participante2025' } }
    /**
     * Find zero or one Participante2025 that matches the filter.
     * @param {Participante2025FindUniqueArgs} args - Arguments to find a Participante2025
     * @example
     * // Get one Participante2025
     * const participante2025 = await prisma.participante2025.findUnique({
     *   where: {
     *     // ... provide filter here
     *   }
     * })
     */
    findUnique<T extends Participante2025FindUniqueArgs>(args: SelectSubset<T, Participante2025FindUniqueArgs<ExtArgs>>): Prisma__Participante2025Client<$Result.GetResult<Prisma.$Participante2025Payload<ExtArgs>, T, "findUnique", GlobalOmitOptions> | null, null, ExtArgs, GlobalOmitOptions>

    /**
     * Find one Participante2025 that matches the filter or throw an error with `error.code='P2025'`
     * if no matches were found.
     * @param {Participante2025FindUniqueOrThrowArgs} args - Arguments to find a Participante2025
     * @example
     * // Get one Participante2025
     * const participante2025 = await prisma.participante2025.findUniqueOrThrow({
     *   where: {
     *     // ... provide filter here
     *   }
     * })
     */
    findUniqueOrThrow<T extends Participante2025FindUniqueOrThrowArgs>(args: SelectSubset<T, Participante2025FindUniqueOrThrowArgs<ExtArgs>>): Prisma__Participante2025Client<$Result.GetResult<Prisma.$Participante2025Payload<ExtArgs>, T, "findUniqueOrThrow", GlobalOmitOptions>, never, ExtArgs, GlobalOmitOptions>

    /**
     * Find the first Participante2025 that matches the filter.
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * @param {Participante2025FindFirstArgs} args - Arguments to find a Participante2025
     * @example
     * // Get one Participante2025
     * const participante2025 = await prisma.participante2025.findFirst({
     *   where: {
     *     // ... provide filter here
     *   }
     * })
     */
    findFirst<T extends Participante2025FindFirstArgs>(args?: SelectSubset<T, Participante2025FindFirstArgs<ExtArgs>>): Prisma__Participante2025Client<$Result.GetResult<Prisma.$Participante2025Payload<ExtArgs>, T, "findFirst", GlobalOmitOptions> | null, null, ExtArgs, GlobalOmitOptions>

    /**
     * Find the first Participante2025 that matches the filter or
     * throw `PrismaKnownClientError` with `P2025` code if no matches were found.
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * @param {Participante2025FindFirstOrThrowArgs} args - Arguments to find a Participante2025
     * @example
     * // Get one Participante2025
     * const participante2025 = await prisma.participante2025.findFirstOrThrow({
     *   where: {
     *     // ... provide filter here
     *   }
     * })
     */
    findFirstOrThrow<T extends Participante2025FindFirstOrThrowArgs>(args?: SelectSubset<T, Participante2025FindFirstOrThrowArgs<ExtArgs>>): Prisma__Participante2025Client<$Result.GetResult<Prisma.$Participante2025Payload<ExtArgs>, T, "findFirstOrThrow", GlobalOmitOptions>, never, ExtArgs, GlobalOmitOptions>

    /**
     * Find zero or more Participante2025s that matches the filter.
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * @param {Participante2025FindManyArgs} args - Arguments to filter and select certain fields only.
     * @example
     * // Get all Participante2025s
     * const participante2025s = await prisma.participante2025.findMany()
     * 
     * // Get first 10 Participante2025s
     * const participante2025s = await prisma.participante2025.findMany({ take: 10 })
     * 
     * // Only select the `id`
     * const participante2025WithIdOnly = await prisma.participante2025.findMany({ select: { id: true } })
     * 
     */
    findMany<T extends Participante2025FindManyArgs>(args?: SelectSubset<T, Participante2025FindManyArgs<ExtArgs>>): Prisma.PrismaPromise<$Result.GetResult<Prisma.$Participante2025Payload<ExtArgs>, T, "findMany", GlobalOmitOptions>>

    /**
     * Create a Participante2025.
     * @param {Participante2025CreateArgs} args - Arguments to create a Participante2025.
     * @example
     * // Create one Participante2025
     * const Participante2025 = await prisma.participante2025.create({
     *   data: {
     *     // ... data to create a Participante2025
     *   }
     * })
     * 
     */
    create<T extends Participante2025CreateArgs>(args: SelectSubset<T, Participante2025CreateArgs<ExtArgs>>): Prisma__Participante2025Client<$Result.GetResult<Prisma.$Participante2025Payload<ExtArgs>, T, "create", GlobalOmitOptions>, never, ExtArgs, GlobalOmitOptions>

    /**
     * Create many Participante2025s.
     * @param {Participante2025CreateManyArgs} args - Arguments to create many Participante2025s.
     * @example
     * // Create many Participante2025s
     * const participante2025 = await prisma.participante2025.createMany({
     *   data: [
     *     // ... provide data here
     *   ]
     * })
     *     
     */
    createMany<T extends Participante2025CreateManyArgs>(args?: SelectSubset<T, Participante2025CreateManyArgs<ExtArgs>>): Prisma.PrismaPromise<BatchPayload>

    /**
     * Create many Participante2025s and returns the data saved in the database.
     * @param {Participante2025CreateManyAndReturnArgs} args - Arguments to create many Participante2025s.
     * @example
     * // Create many Participante2025s
     * const participante2025 = await prisma.participante2025.createManyAndReturn({
     *   data: [
     *     // ... provide data here
     *   ]
     * })
     * 
     * // Create many Participante2025s and only return the `id`
     * const participante2025WithIdOnly = await prisma.participante2025.createManyAndReturn({
     *   select: { id: true },
     *   data: [
     *     // ... provide data here
     *   ]
     * })
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * 
     */
    createManyAndReturn<T extends Participante2025CreateManyAndReturnArgs>(args?: SelectSubset<T, Participante2025CreateManyAndReturnArgs<ExtArgs>>): Prisma.PrismaPromise<$Result.GetResult<Prisma.$Participante2025Payload<ExtArgs>, T, "createManyAndReturn", GlobalOmitOptions>>

    /**
     * Delete a Participante2025.
     * @param {Participante2025DeleteArgs} args - Arguments to delete one Participante2025.
     * @example
     * // Delete one Participante2025
     * const Participante2025 = await prisma.participante2025.delete({
     *   where: {
     *     // ... filter to delete one Participante2025
     *   }
     * })
     * 
     */
    delete<T extends Participante2025DeleteArgs>(args: SelectSubset<T, Participante2025DeleteArgs<ExtArgs>>): Prisma__Participante2025Client<$Result.GetResult<Prisma.$Participante2025Payload<ExtArgs>, T, "delete", GlobalOmitOptions>, never, ExtArgs, GlobalOmitOptions>

    /**
     * Update one Participante2025.
     * @param {Participante2025UpdateArgs} args - Arguments to update one Participante2025.
     * @example
     * // Update one Participante2025
     * const participante2025 = await prisma.participante2025.update({
     *   where: {
     *     // ... provide filter here
     *   },
     *   data: {
     *     // ... provide data here
     *   }
     * })
     * 
     */
    update<T extends Participante2025UpdateArgs>(args: SelectSubset<T, Participante2025UpdateArgs<ExtArgs>>): Prisma__Participante2025Client<$Result.GetResult<Prisma.$Participante2025Payload<ExtArgs>, T, "update", GlobalOmitOptions>, never, ExtArgs, GlobalOmitOptions>

    /**
     * Delete zero or more Participante2025s.
     * @param {Participante2025DeleteManyArgs} args - Arguments to filter Participante2025s to delete.
     * @example
     * // Delete a few Participante2025s
     * const { count } = await prisma.participante2025.deleteMany({
     *   where: {
     *     // ... provide filter here
     *   }
     * })
     * 
     */
    deleteMany<T extends Participante2025DeleteManyArgs>(args?: SelectSubset<T, Participante2025DeleteManyArgs<ExtArgs>>): Prisma.PrismaPromise<BatchPayload>

    /**
     * Update zero or more Participante2025s.
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * @param {Participante2025UpdateManyArgs} args - Arguments to update one or more rows.
     * @example
     * // Update many Participante2025s
     * const participante2025 = await prisma.participante2025.updateMany({
     *   where: {
     *     // ... provide filter here
     *   },
     *   data: {
     *     // ... provide data here
     *   }
     * })
     * 
     */
    updateMany<T extends Participante2025UpdateManyArgs>(args: SelectSubset<T, Participante2025UpdateManyArgs<ExtArgs>>): Prisma.PrismaPromise<BatchPayload>

    /**
     * Update zero or more Participante2025s and returns the data updated in the database.
     * @param {Participante2025UpdateManyAndReturnArgs} args - Arguments to update many Participante2025s.
     * @example
     * // Update many Participante2025s
     * const participante2025 = await prisma.participante2025.updateManyAndReturn({
     *   where: {
     *     // ... provide filter here
     *   },
     *   data: [
     *     // ... provide data here
     *   ]
     * })
     * 
     * // Update zero or more Participante2025s and only return the `id`
     * const participante2025WithIdOnly = await prisma.participante2025.updateManyAndReturn({
     *   select: { id: true },
     *   where: {
     *     // ... provide filter here
     *   },
     *   data: [
     *     // ... provide data here
     *   ]
     * })
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * 
     */
    updateManyAndReturn<T extends Participante2025UpdateManyAndReturnArgs>(args: SelectSubset<T, Participante2025UpdateManyAndReturnArgs<ExtArgs>>): Prisma.PrismaPromise<$Result.GetResult<Prisma.$Participante2025Payload<ExtArgs>, T, "updateManyAndReturn", GlobalOmitOptions>>

    /**
     * Create or update one Participante2025.
     * @param {Participante2025UpsertArgs} args - Arguments to update or create a Participante2025.
     * @example
     * // Update or create a Participante2025
     * const participante2025 = await prisma.participante2025.upsert({
     *   create: {
     *     // ... data to create a Participante2025
     *   },
     *   update: {
     *     // ... in case it already exists, update
     *   },
     *   where: {
     *     // ... the filter for the Participante2025 we want to update
     *   }
     * })
     */
    upsert<T extends Participante2025UpsertArgs>(args: SelectSubset<T, Participante2025UpsertArgs<ExtArgs>>): Prisma__Participante2025Client<$Result.GetResult<Prisma.$Participante2025Payload<ExtArgs>, T, "upsert", GlobalOmitOptions>, never, ExtArgs, GlobalOmitOptions>


    /**
     * Count the number of Participante2025s.
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * @param {Participante2025CountArgs} args - Arguments to filter Participante2025s to count.
     * @example
     * // Count the number of Participante2025s
     * const count = await prisma.participante2025.count({
     *   where: {
     *     // ... the filter for the Participante2025s we want to count
     *   }
     * })
    **/
    count<T extends Participante2025CountArgs>(
      args?: Subset<T, Participante2025CountArgs>,
    ): Prisma.PrismaPromise<
      T extends $Utils.Record<'select', any>
        ? T['select'] extends true
          ? number
          : GetScalarType<T['select'], Participante2025CountAggregateOutputType>
        : number
    >

    /**
     * Allows you to perform aggregations operations on a Participante2025.
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * @param {Participante2025AggregateArgs} args - Select which aggregations you would like to apply and on what fields.
     * @example
     * // Ordered by age ascending
     * // Where email contains prisma.io
     * // Limited to the 10 users
     * const aggregations = await prisma.user.aggregate({
     *   _avg: {
     *     age: true,
     *   },
     *   where: {
     *     email: {
     *       contains: "prisma.io",
     *     },
     *   },
     *   orderBy: {
     *     age: "asc",
     *   },
     *   take: 10,
     * })
    **/
    aggregate<T extends Participante2025AggregateArgs>(args: Subset<T, Participante2025AggregateArgs>): Prisma.PrismaPromise<GetParticipante2025AggregateType<T>>

    /**
     * Group by Participante2025.
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * @param {Participante2025GroupByArgs} args - Group by arguments.
     * @example
     * // Group by city, order by createdAt, get count
     * const result = await prisma.user.groupBy({
     *   by: ['city', 'createdAt'],
     *   orderBy: {
     *     createdAt: true
     *   },
     *   _count: {
     *     _all: true
     *   },
     * })
     * 
    **/
    groupBy<
      T extends Participante2025GroupByArgs,
      HasSelectOrTake extends Or<
        Extends<'skip', Keys<T>>,
        Extends<'take', Keys<T>>
      >,
      OrderByArg extends True extends HasSelectOrTake
        ? { orderBy: Participante2025GroupByArgs['orderBy'] }
        : { orderBy?: Participante2025GroupByArgs['orderBy'] },
      OrderFields extends ExcludeUnderscoreKeys<Keys<MaybeTupleToUnion<T['orderBy']>>>,
      ByFields extends MaybeTupleToUnion<T['by']>,
      ByValid extends Has<ByFields, OrderFields>,
      HavingFields extends GetHavingFields<T['having']>,
      HavingValid extends Has<ByFields, HavingFields>,
      ByEmpty extends T['by'] extends never[] ? True : False,
      InputErrors extends ByEmpty extends True
      ? `Error: "by" must not be empty.`
      : HavingValid extends False
      ? {
          [P in HavingFields]: P extends ByFields
            ? never
            : P extends string
            ? `Error: Field "${P}" used in "having" needs to be provided in "by".`
            : [
                Error,
                'Field ',
                P,
                ` in "having" needs to be provided in "by"`,
              ]
        }[HavingFields]
      : 'take' extends Keys<T>
      ? 'orderBy' extends Keys<T>
        ? ByValid extends True
          ? {}
          : {
              [P in OrderFields]: P extends ByFields
                ? never
                : `Error: Field "${P}" in "orderBy" needs to be provided in "by"`
            }[OrderFields]
        : 'Error: If you provide "take", you also need to provide "orderBy"'
      : 'skip' extends Keys<T>
      ? 'orderBy' extends Keys<T>
        ? ByValid extends True
          ? {}
          : {
              [P in OrderFields]: P extends ByFields
                ? never
                : `Error: Field "${P}" in "orderBy" needs to be provided in "by"`
            }[OrderFields]
        : 'Error: If you provide "skip", you also need to provide "orderBy"'
      : ByValid extends True
      ? {}
      : {
          [P in OrderFields]: P extends ByFields
            ? never
            : `Error: Field "${P}" in "orderBy" needs to be provided in "by"`
        }[OrderFields]
    >(args: SubsetIntersection<T, Participante2025GroupByArgs, OrderByArg> & InputErrors): {} extends InputErrors ? GetParticipante2025GroupByPayload<T> : Prisma.PrismaPromise<InputErrors>
  /**
   * Fields of the Participante2025 model
   */
  readonly fields: Participante2025FieldRefs;
  }

  /**
   * The delegate class that acts as a "Promise-like" for Participante2025.
   * Why is this prefixed with `Prisma__`?
   * Because we want to prevent naming conflicts as mentioned in
   * https://github.com/prisma/prisma-client-js/issues/707
   */
  export interface Prisma__Participante2025Client<T, Null = never, ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs, GlobalOmitOptions = {}> extends Prisma.PrismaPromise<T> {
    readonly [Symbol.toStringTag]: "PrismaPromise"
    instituicao<T extends Participante2025$instituicaoArgs<ExtArgs> = {}>(args?: Subset<T, Participante2025$instituicaoArgs<ExtArgs>>): Prisma__InstituicaoEspiritaClient<$Result.GetResult<Prisma.$InstituicaoEspiritaPayload<ExtArgs>, T, "findUniqueOrThrow", GlobalOmitOptions> | null, null, ExtArgs, GlobalOmitOptions>
    user<T extends Participante2025$userArgs<ExtArgs> = {}>(args?: Subset<T, Participante2025$userArgs<ExtArgs>>): Prisma__UsersClient<$Result.GetResult<Prisma.$UsersPayload<ExtArgs>, T, "findUniqueOrThrow", GlobalOmitOptions> | null, null, ExtArgs, GlobalOmitOptions>
    /**
     * Attaches callbacks for the resolution and/or rejection of the Promise.
     * @param onfulfilled The callback to execute when the Promise is resolved.
     * @param onrejected The callback to execute when the Promise is rejected.
     * @returns A Promise for the completion of which ever callback is executed.
     */
    then<TResult1 = T, TResult2 = never>(onfulfilled?: ((value: T) => TResult1 | PromiseLike<TResult1>) | undefined | null, onrejected?: ((reason: any) => TResult2 | PromiseLike<TResult2>) | undefined | null): $Utils.JsPromise<TResult1 | TResult2>
    /**
     * Attaches a callback for only the rejection of the Promise.
     * @param onrejected The callback to execute when the Promise is rejected.
     * @returns A Promise for the completion of the callback.
     */
    catch<TResult = never>(onrejected?: ((reason: any) => TResult | PromiseLike<TResult>) | undefined | null): $Utils.JsPromise<T | TResult>
    /**
     * Attaches a callback that is invoked when the Promise is settled (fulfilled or rejected). The
     * resolved value cannot be modified from the callback.
     * @param onfinally The callback to execute when the Promise is settled (fulfilled or rejected).
     * @returns A Promise for the completion of the callback.
     */
    finally(onfinally?: (() => void) | undefined | null): $Utils.JsPromise<T>
  }




  /**
   * Fields of the Participante2025 model
   */
  interface Participante2025FieldRefs {
    readonly id: FieldRef<"Participante2025", 'String'>
    readonly nomeCompleto: FieldRef<"Participante2025", 'String'>
    readonly nomeCracha: FieldRef<"Participante2025", 'String'>
    readonly cpf: FieldRef<"Participante2025", 'String'>
    readonly nomeSocial: FieldRef<"Participante2025", 'String'>
    readonly dataNascimento: FieldRef<"Participante2025", 'DateTime'>
    readonly sexo: FieldRef<"Participante2025", 'String'>
    readonly email: FieldRef<"Participante2025", 'String'>
    readonly telefone: FieldRef<"Participante2025", 'String'>
    readonly nomeCompletoResponsavel: FieldRef<"Participante2025", 'String'>
    readonly documentoResponsavel: FieldRef<"Participante2025", 'String'>
    readonly telefoneResponsavel: FieldRef<"Participante2025", 'String'>
    readonly linkPagamento: FieldRef<"Participante2025", 'String'>
    readonly idade: FieldRef<"Participante2025", 'Int'>
    readonly valor: FieldRef<"Participante2025", 'Float'>
    readonly statusPagamento: FieldRef<"Participante2025", 'String'>
    readonly tipoParticipacao: FieldRef<"Participante2025", 'TipoParticipacao'>
    readonly comissao: FieldRef<"Participante2025", 'String'>
    readonly tamanhoCamisa: FieldRef<"Participante2025", 'String'>
    readonly cep: FieldRef<"Participante2025", 'String'>
    readonly estado: FieldRef<"Participante2025", 'String'>
    readonly cidade: FieldRef<"Participante2025", 'String'>
    readonly bairro: FieldRef<"Participante2025", 'String'>
    readonly logradouro: FieldRef<"Participante2025", 'String'>
    readonly numero: FieldRef<"Participante2025", 'String'>
    readonly complemento: FieldRef<"Participante2025", 'String'>
    readonly outroGenero: FieldRef<"Participante2025", 'String'>
    readonly medicacao: FieldRef<"Participante2025", 'String'>
    readonly alergia: FieldRef<"Participante2025", 'String'>
    readonly outrasInformacoes: FieldRef<"Participante2025", 'String'>
    readonly userId: FieldRef<"Participante2025", 'Int'>
    readonly createdAt: FieldRef<"Participante2025", 'DateTime'>
    readonly updatedAt: FieldRef<"Participante2025", 'DateTime'>
    readonly IE: FieldRef<"Participante2025", 'String'>
    readonly instituicaoId: FieldRef<"Participante2025", 'Int'>
    readonly vegetariano: FieldRef<"Participante2025", 'String'>
    readonly camisa: FieldRef<"Participante2025", 'Boolean'>
    readonly primeiraComejaca: FieldRef<"Participante2025", 'Boolean'>
    readonly deficienciaAuditiva: FieldRef<"Participante2025", 'Boolean'>
    readonly deficienciaAutismo: FieldRef<"Participante2025", 'Boolean'>
    readonly deficienciaIntelectual: FieldRef<"Participante2025", 'Boolean'>
    readonly deficienciaParalisiaCerebral: FieldRef<"Participante2025", 'Boolean'>
    readonly deficienciaVisual: FieldRef<"Participante2025", 'Boolean'>
    readonly deficienciaFisica: FieldRef<"Participante2025", 'Boolean'>
    readonly deficienciaOutra: FieldRef<"Participante2025", 'Boolean'>
    readonly deficienciaOutraDescricao: FieldRef<"Participante2025", 'String'>
    readonly otherInstitution: FieldRef<"Participante2025", 'String'>
  }
    

  // Custom InputTypes
  /**
   * Participante2025 findUnique
   */
  export type Participante2025FindUniqueArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the Participante2025
     */
    select?: Participante2025Select<ExtArgs> | null
    /**
     * Omit specific fields from the Participante2025
     */
    omit?: Participante2025Omit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: Participante2025Include<ExtArgs> | null
    /**
     * Filter, which Participante2025 to fetch.
     */
    where: Participante2025WhereUniqueInput
  }

  /**
   * Participante2025 findUniqueOrThrow
   */
  export type Participante2025FindUniqueOrThrowArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the Participante2025
     */
    select?: Participante2025Select<ExtArgs> | null
    /**
     * Omit specific fields from the Participante2025
     */
    omit?: Participante2025Omit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: Participante2025Include<ExtArgs> | null
    /**
     * Filter, which Participante2025 to fetch.
     */
    where: Participante2025WhereUniqueInput
  }

  /**
   * Participante2025 findFirst
   */
  export type Participante2025FindFirstArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the Participante2025
     */
    select?: Participante2025Select<ExtArgs> | null
    /**
     * Omit specific fields from the Participante2025
     */
    omit?: Participante2025Omit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: Participante2025Include<ExtArgs> | null
    /**
     * Filter, which Participante2025 to fetch.
     */
    where?: Participante2025WhereInput
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/sorting Sorting Docs}
     * 
     * Determine the order of Participante2025s to fetch.
     */
    orderBy?: Participante2025OrderByWithRelationInput | Participante2025OrderByWithRelationInput[]
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination#cursor-based-pagination Cursor Docs}
     * 
     * Sets the position for searching for Participante2025s.
     */
    cursor?: Participante2025WhereUniqueInput
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination Pagination Docs}
     * 
     * Take `±n` Participante2025s from the position of the cursor.
     */
    take?: number
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination Pagination Docs}
     * 
     * Skip the first `n` Participante2025s.
     */
    skip?: number
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/distinct Distinct Docs}
     * 
     * Filter by unique combinations of Participante2025s.
     */
    distinct?: Participante2025ScalarFieldEnum | Participante2025ScalarFieldEnum[]
  }

  /**
   * Participante2025 findFirstOrThrow
   */
  export type Participante2025FindFirstOrThrowArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the Participante2025
     */
    select?: Participante2025Select<ExtArgs> | null
    /**
     * Omit specific fields from the Participante2025
     */
    omit?: Participante2025Omit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: Participante2025Include<ExtArgs> | null
    /**
     * Filter, which Participante2025 to fetch.
     */
    where?: Participante2025WhereInput
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/sorting Sorting Docs}
     * 
     * Determine the order of Participante2025s to fetch.
     */
    orderBy?: Participante2025OrderByWithRelationInput | Participante2025OrderByWithRelationInput[]
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination#cursor-based-pagination Cursor Docs}
     * 
     * Sets the position for searching for Participante2025s.
     */
    cursor?: Participante2025WhereUniqueInput
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination Pagination Docs}
     * 
     * Take `±n` Participante2025s from the position of the cursor.
     */
    take?: number
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination Pagination Docs}
     * 
     * Skip the first `n` Participante2025s.
     */
    skip?: number
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/distinct Distinct Docs}
     * 
     * Filter by unique combinations of Participante2025s.
     */
    distinct?: Participante2025ScalarFieldEnum | Participante2025ScalarFieldEnum[]
  }

  /**
   * Participante2025 findMany
   */
  export type Participante2025FindManyArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the Participante2025
     */
    select?: Participante2025Select<ExtArgs> | null
    /**
     * Omit specific fields from the Participante2025
     */
    omit?: Participante2025Omit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: Participante2025Include<ExtArgs> | null
    /**
     * Filter, which Participante2025s to fetch.
     */
    where?: Participante2025WhereInput
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/sorting Sorting Docs}
     * 
     * Determine the order of Participante2025s to fetch.
     */
    orderBy?: Participante2025OrderByWithRelationInput | Participante2025OrderByWithRelationInput[]
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination#cursor-based-pagination Cursor Docs}
     * 
     * Sets the position for listing Participante2025s.
     */
    cursor?: Participante2025WhereUniqueInput
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination Pagination Docs}
     * 
     * Take `±n` Participante2025s from the position of the cursor.
     */
    take?: number
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination Pagination Docs}
     * 
     * Skip the first `n` Participante2025s.
     */
    skip?: number
    distinct?: Participante2025ScalarFieldEnum | Participante2025ScalarFieldEnum[]
  }

  /**
   * Participante2025 create
   */
  export type Participante2025CreateArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the Participante2025
     */
    select?: Participante2025Select<ExtArgs> | null
    /**
     * Omit specific fields from the Participante2025
     */
    omit?: Participante2025Omit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: Participante2025Include<ExtArgs> | null
    /**
     * The data needed to create a Participante2025.
     */
    data: XOR<Participante2025CreateInput, Participante2025UncheckedCreateInput>
  }

  /**
   * Participante2025 createMany
   */
  export type Participante2025CreateManyArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * The data used to create many Participante2025s.
     */
    data: Participante2025CreateManyInput | Participante2025CreateManyInput[]
    skipDuplicates?: boolean
  }

  /**
   * Participante2025 createManyAndReturn
   */
  export type Participante2025CreateManyAndReturnArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the Participante2025
     */
    select?: Participante2025SelectCreateManyAndReturn<ExtArgs> | null
    /**
     * Omit specific fields from the Participante2025
     */
    omit?: Participante2025Omit<ExtArgs> | null
    /**
     * The data used to create many Participante2025s.
     */
    data: Participante2025CreateManyInput | Participante2025CreateManyInput[]
    skipDuplicates?: boolean
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: Participante2025IncludeCreateManyAndReturn<ExtArgs> | null
  }

  /**
   * Participante2025 update
   */
  export type Participante2025UpdateArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the Participante2025
     */
    select?: Participante2025Select<ExtArgs> | null
    /**
     * Omit specific fields from the Participante2025
     */
    omit?: Participante2025Omit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: Participante2025Include<ExtArgs> | null
    /**
     * The data needed to update a Participante2025.
     */
    data: XOR<Participante2025UpdateInput, Participante2025UncheckedUpdateInput>
    /**
     * Choose, which Participante2025 to update.
     */
    where: Participante2025WhereUniqueInput
  }

  /**
   * Participante2025 updateMany
   */
  export type Participante2025UpdateManyArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * The data used to update Participante2025s.
     */
    data: XOR<Participante2025UpdateManyMutationInput, Participante2025UncheckedUpdateManyInput>
    /**
     * Filter which Participante2025s to update
     */
    where?: Participante2025WhereInput
    /**
     * Limit how many Participante2025s to update.
     */
    limit?: number
  }

  /**
   * Participante2025 updateManyAndReturn
   */
  export type Participante2025UpdateManyAndReturnArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the Participante2025
     */
    select?: Participante2025SelectUpdateManyAndReturn<ExtArgs> | null
    /**
     * Omit specific fields from the Participante2025
     */
    omit?: Participante2025Omit<ExtArgs> | null
    /**
     * The data used to update Participante2025s.
     */
    data: XOR<Participante2025UpdateManyMutationInput, Participante2025UncheckedUpdateManyInput>
    /**
     * Filter which Participante2025s to update
     */
    where?: Participante2025WhereInput
    /**
     * Limit how many Participante2025s to update.
     */
    limit?: number
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: Participante2025IncludeUpdateManyAndReturn<ExtArgs> | null
  }

  /**
   * Participante2025 upsert
   */
  export type Participante2025UpsertArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the Participante2025
     */
    select?: Participante2025Select<ExtArgs> | null
    /**
     * Omit specific fields from the Participante2025
     */
    omit?: Participante2025Omit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: Participante2025Include<ExtArgs> | null
    /**
     * The filter to search for the Participante2025 to update in case it exists.
     */
    where: Participante2025WhereUniqueInput
    /**
     * In case the Participante2025 found by the `where` argument doesn't exist, create a new Participante2025 with this data.
     */
    create: XOR<Participante2025CreateInput, Participante2025UncheckedCreateInput>
    /**
     * In case the Participante2025 was found with the provided `where` argument, update it with this data.
     */
    update: XOR<Participante2025UpdateInput, Participante2025UncheckedUpdateInput>
  }

  /**
   * Participante2025 delete
   */
  export type Participante2025DeleteArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the Participante2025
     */
    select?: Participante2025Select<ExtArgs> | null
    /**
     * Omit specific fields from the Participante2025
     */
    omit?: Participante2025Omit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: Participante2025Include<ExtArgs> | null
    /**
     * Filter which Participante2025 to delete.
     */
    where: Participante2025WhereUniqueInput
  }

  /**
   * Participante2025 deleteMany
   */
  export type Participante2025DeleteManyArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Filter which Participante2025s to delete
     */
    where?: Participante2025WhereInput
    /**
     * Limit how many Participante2025s to delete.
     */
    limit?: number
  }

  /**
   * Participante2025.instituicao
   */
  export type Participante2025$instituicaoArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the InstituicaoEspirita
     */
    select?: InstituicaoEspiritaSelect<ExtArgs> | null
    /**
     * Omit specific fields from the InstituicaoEspirita
     */
    omit?: InstituicaoEspiritaOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: InstituicaoEspiritaInclude<ExtArgs> | null
    where?: InstituicaoEspiritaWhereInput
  }

  /**
   * Participante2025.user
   */
  export type Participante2025$userArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the Users
     */
    select?: UsersSelect<ExtArgs> | null
    /**
     * Omit specific fields from the Users
     */
    omit?: UsersOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: UsersInclude<ExtArgs> | null
    where?: UsersWhereInput
  }

  /**
   * Participante2025 without action
   */
  export type Participante2025DefaultArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the Participante2025
     */
    select?: Participante2025Select<ExtArgs> | null
    /**
     * Omit specific fields from the Participante2025
     */
    omit?: Participante2025Omit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: Participante2025Include<ExtArgs> | null
  }


  /**
   * Model PasswordResetToken
   */

  export type AggregatePasswordResetToken = {
    _count: PasswordResetTokenCountAggregateOutputType | null
    _avg: PasswordResetTokenAvgAggregateOutputType | null
    _sum: PasswordResetTokenSumAggregateOutputType | null
    _min: PasswordResetTokenMinAggregateOutputType | null
    _max: PasswordResetTokenMaxAggregateOutputType | null
  }

  export type PasswordResetTokenAvgAggregateOutputType = {
    id: number | null
    userId: number | null
  }

  export type PasswordResetTokenSumAggregateOutputType = {
    id: number | null
    userId: number | null
  }

  export type PasswordResetTokenMinAggregateOutputType = {
    id: number | null
    token: string | null
    userId: number | null
    expiresAt: Date | null
    createdAt: Date | null
  }

  export type PasswordResetTokenMaxAggregateOutputType = {
    id: number | null
    token: string | null
    userId: number | null
    expiresAt: Date | null
    createdAt: Date | null
  }

  export type PasswordResetTokenCountAggregateOutputType = {
    id: number
    token: number
    userId: number
    expiresAt: number
    createdAt: number
    _all: number
  }


  export type PasswordResetTokenAvgAggregateInputType = {
    id?: true
    userId?: true
  }

  export type PasswordResetTokenSumAggregateInputType = {
    id?: true
    userId?: true
  }

  export type PasswordResetTokenMinAggregateInputType = {
    id?: true
    token?: true
    userId?: true
    expiresAt?: true
    createdAt?: true
  }

  export type PasswordResetTokenMaxAggregateInputType = {
    id?: true
    token?: true
    userId?: true
    expiresAt?: true
    createdAt?: true
  }

  export type PasswordResetTokenCountAggregateInputType = {
    id?: true
    token?: true
    userId?: true
    expiresAt?: true
    createdAt?: true
    _all?: true
  }

  export type PasswordResetTokenAggregateArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Filter which PasswordResetToken to aggregate.
     */
    where?: PasswordResetTokenWhereInput
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/sorting Sorting Docs}
     * 
     * Determine the order of PasswordResetTokens to fetch.
     */
    orderBy?: PasswordResetTokenOrderByWithRelationInput | PasswordResetTokenOrderByWithRelationInput[]
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination#cursor-based-pagination Cursor Docs}
     * 
     * Sets the start position
     */
    cursor?: PasswordResetTokenWhereUniqueInput
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination Pagination Docs}
     * 
     * Take `±n` PasswordResetTokens from the position of the cursor.
     */
    take?: number
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination Pagination Docs}
     * 
     * Skip the first `n` PasswordResetTokens.
     */
    skip?: number
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/aggregations Aggregation Docs}
     * 
     * Count returned PasswordResetTokens
    **/
    _count?: true | PasswordResetTokenCountAggregateInputType
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/aggregations Aggregation Docs}
     * 
     * Select which fields to average
    **/
    _avg?: PasswordResetTokenAvgAggregateInputType
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/aggregations Aggregation Docs}
     * 
     * Select which fields to sum
    **/
    _sum?: PasswordResetTokenSumAggregateInputType
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/aggregations Aggregation Docs}
     * 
     * Select which fields to find the minimum value
    **/
    _min?: PasswordResetTokenMinAggregateInputType
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/aggregations Aggregation Docs}
     * 
     * Select which fields to find the maximum value
    **/
    _max?: PasswordResetTokenMaxAggregateInputType
  }

  export type GetPasswordResetTokenAggregateType<T extends PasswordResetTokenAggregateArgs> = {
        [P in keyof T & keyof AggregatePasswordResetToken]: P extends '_count' | 'count'
      ? T[P] extends true
        ? number
        : GetScalarType<T[P], AggregatePasswordResetToken[P]>
      : GetScalarType<T[P], AggregatePasswordResetToken[P]>
  }




  export type PasswordResetTokenGroupByArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    where?: PasswordResetTokenWhereInput
    orderBy?: PasswordResetTokenOrderByWithAggregationInput | PasswordResetTokenOrderByWithAggregationInput[]
    by: PasswordResetTokenScalarFieldEnum[] | PasswordResetTokenScalarFieldEnum
    having?: PasswordResetTokenScalarWhereWithAggregatesInput
    take?: number
    skip?: number
    _count?: PasswordResetTokenCountAggregateInputType | true
    _avg?: PasswordResetTokenAvgAggregateInputType
    _sum?: PasswordResetTokenSumAggregateInputType
    _min?: PasswordResetTokenMinAggregateInputType
    _max?: PasswordResetTokenMaxAggregateInputType
  }

  export type PasswordResetTokenGroupByOutputType = {
    id: number
    token: string
    userId: number
    expiresAt: Date
    createdAt: Date
    _count: PasswordResetTokenCountAggregateOutputType | null
    _avg: PasswordResetTokenAvgAggregateOutputType | null
    _sum: PasswordResetTokenSumAggregateOutputType | null
    _min: PasswordResetTokenMinAggregateOutputType | null
    _max: PasswordResetTokenMaxAggregateOutputType | null
  }

  type GetPasswordResetTokenGroupByPayload<T extends PasswordResetTokenGroupByArgs> = Prisma.PrismaPromise<
    Array<
      PickEnumerable<PasswordResetTokenGroupByOutputType, T['by']> &
        {
          [P in ((keyof T) & (keyof PasswordResetTokenGroupByOutputType))]: P extends '_count'
            ? T[P] extends boolean
              ? number
              : GetScalarType<T[P], PasswordResetTokenGroupByOutputType[P]>
            : GetScalarType<T[P], PasswordResetTokenGroupByOutputType[P]>
        }
      >
    >


  export type PasswordResetTokenSelect<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = $Extensions.GetSelect<{
    id?: boolean
    token?: boolean
    userId?: boolean
    expiresAt?: boolean
    createdAt?: boolean
    user?: boolean | UsersDefaultArgs<ExtArgs>
  }, ExtArgs["result"]["passwordResetToken"]>

  export type PasswordResetTokenSelectCreateManyAndReturn<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = $Extensions.GetSelect<{
    id?: boolean
    token?: boolean
    userId?: boolean
    expiresAt?: boolean
    createdAt?: boolean
    user?: boolean | UsersDefaultArgs<ExtArgs>
  }, ExtArgs["result"]["passwordResetToken"]>

  export type PasswordResetTokenSelectUpdateManyAndReturn<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = $Extensions.GetSelect<{
    id?: boolean
    token?: boolean
    userId?: boolean
    expiresAt?: boolean
    createdAt?: boolean
    user?: boolean | UsersDefaultArgs<ExtArgs>
  }, ExtArgs["result"]["passwordResetToken"]>

  export type PasswordResetTokenSelectScalar = {
    id?: boolean
    token?: boolean
    userId?: boolean
    expiresAt?: boolean
    createdAt?: boolean
  }

  export type PasswordResetTokenOmit<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = $Extensions.GetOmit<"id" | "token" | "userId" | "expiresAt" | "createdAt", ExtArgs["result"]["passwordResetToken"]>
  export type PasswordResetTokenInclude<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    user?: boolean | UsersDefaultArgs<ExtArgs>
  }
  export type PasswordResetTokenIncludeCreateManyAndReturn<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    user?: boolean | UsersDefaultArgs<ExtArgs>
  }
  export type PasswordResetTokenIncludeUpdateManyAndReturn<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    user?: boolean | UsersDefaultArgs<ExtArgs>
  }

  export type $PasswordResetTokenPayload<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    name: "PasswordResetToken"
    objects: {
      user: Prisma.$UsersPayload<ExtArgs>
    }
    scalars: $Extensions.GetPayloadResult<{
      id: number
      token: string
      userId: number
      expiresAt: Date
      createdAt: Date
    }, ExtArgs["result"]["passwordResetToken"]>
    composites: {}
  }

  type PasswordResetTokenGetPayload<S extends boolean | null | undefined | PasswordResetTokenDefaultArgs> = $Result.GetResult<Prisma.$PasswordResetTokenPayload, S>

  type PasswordResetTokenCountArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> =
    Omit<PasswordResetTokenFindManyArgs, 'select' | 'include' | 'distinct' | 'omit'> & {
      select?: PasswordResetTokenCountAggregateInputType | true
    }

  export interface PasswordResetTokenDelegate<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs, GlobalOmitOptions = {}> {
    [K: symbol]: { types: Prisma.TypeMap<ExtArgs>['model']['PasswordResetToken'], meta: { name: 'PasswordResetToken' } }
    /**
     * Find zero or one PasswordResetToken that matches the filter.
     * @param {PasswordResetTokenFindUniqueArgs} args - Arguments to find a PasswordResetToken
     * @example
     * // Get one PasswordResetToken
     * const passwordResetToken = await prisma.passwordResetToken.findUnique({
     *   where: {
     *     // ... provide filter here
     *   }
     * })
     */
    findUnique<T extends PasswordResetTokenFindUniqueArgs>(args: SelectSubset<T, PasswordResetTokenFindUniqueArgs<ExtArgs>>): Prisma__PasswordResetTokenClient<$Result.GetResult<Prisma.$PasswordResetTokenPayload<ExtArgs>, T, "findUnique", GlobalOmitOptions> | null, null, ExtArgs, GlobalOmitOptions>

    /**
     * Find one PasswordResetToken that matches the filter or throw an error with `error.code='P2025'`
     * if no matches were found.
     * @param {PasswordResetTokenFindUniqueOrThrowArgs} args - Arguments to find a PasswordResetToken
     * @example
     * // Get one PasswordResetToken
     * const passwordResetToken = await prisma.passwordResetToken.findUniqueOrThrow({
     *   where: {
     *     // ... provide filter here
     *   }
     * })
     */
    findUniqueOrThrow<T extends PasswordResetTokenFindUniqueOrThrowArgs>(args: SelectSubset<T, PasswordResetTokenFindUniqueOrThrowArgs<ExtArgs>>): Prisma__PasswordResetTokenClient<$Result.GetResult<Prisma.$PasswordResetTokenPayload<ExtArgs>, T, "findUniqueOrThrow", GlobalOmitOptions>, never, ExtArgs, GlobalOmitOptions>

    /**
     * Find the first PasswordResetToken that matches the filter.
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * @param {PasswordResetTokenFindFirstArgs} args - Arguments to find a PasswordResetToken
     * @example
     * // Get one PasswordResetToken
     * const passwordResetToken = await prisma.passwordResetToken.findFirst({
     *   where: {
     *     // ... provide filter here
     *   }
     * })
     */
    findFirst<T extends PasswordResetTokenFindFirstArgs>(args?: SelectSubset<T, PasswordResetTokenFindFirstArgs<ExtArgs>>): Prisma__PasswordResetTokenClient<$Result.GetResult<Prisma.$PasswordResetTokenPayload<ExtArgs>, T, "findFirst", GlobalOmitOptions> | null, null, ExtArgs, GlobalOmitOptions>

    /**
     * Find the first PasswordResetToken that matches the filter or
     * throw `PrismaKnownClientError` with `P2025` code if no matches were found.
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * @param {PasswordResetTokenFindFirstOrThrowArgs} args - Arguments to find a PasswordResetToken
     * @example
     * // Get one PasswordResetToken
     * const passwordResetToken = await prisma.passwordResetToken.findFirstOrThrow({
     *   where: {
     *     // ... provide filter here
     *   }
     * })
     */
    findFirstOrThrow<T extends PasswordResetTokenFindFirstOrThrowArgs>(args?: SelectSubset<T, PasswordResetTokenFindFirstOrThrowArgs<ExtArgs>>): Prisma__PasswordResetTokenClient<$Result.GetResult<Prisma.$PasswordResetTokenPayload<ExtArgs>, T, "findFirstOrThrow", GlobalOmitOptions>, never, ExtArgs, GlobalOmitOptions>

    /**
     * Find zero or more PasswordResetTokens that matches the filter.
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * @param {PasswordResetTokenFindManyArgs} args - Arguments to filter and select certain fields only.
     * @example
     * // Get all PasswordResetTokens
     * const passwordResetTokens = await prisma.passwordResetToken.findMany()
     * 
     * // Get first 10 PasswordResetTokens
     * const passwordResetTokens = await prisma.passwordResetToken.findMany({ take: 10 })
     * 
     * // Only select the `id`
     * const passwordResetTokenWithIdOnly = await prisma.passwordResetToken.findMany({ select: { id: true } })
     * 
     */
    findMany<T extends PasswordResetTokenFindManyArgs>(args?: SelectSubset<T, PasswordResetTokenFindManyArgs<ExtArgs>>): Prisma.PrismaPromise<$Result.GetResult<Prisma.$PasswordResetTokenPayload<ExtArgs>, T, "findMany", GlobalOmitOptions>>

    /**
     * Create a PasswordResetToken.
     * @param {PasswordResetTokenCreateArgs} args - Arguments to create a PasswordResetToken.
     * @example
     * // Create one PasswordResetToken
     * const PasswordResetToken = await prisma.passwordResetToken.create({
     *   data: {
     *     // ... data to create a PasswordResetToken
     *   }
     * })
     * 
     */
    create<T extends PasswordResetTokenCreateArgs>(args: SelectSubset<T, PasswordResetTokenCreateArgs<ExtArgs>>): Prisma__PasswordResetTokenClient<$Result.GetResult<Prisma.$PasswordResetTokenPayload<ExtArgs>, T, "create", GlobalOmitOptions>, never, ExtArgs, GlobalOmitOptions>

    /**
     * Create many PasswordResetTokens.
     * @param {PasswordResetTokenCreateManyArgs} args - Arguments to create many PasswordResetTokens.
     * @example
     * // Create many PasswordResetTokens
     * const passwordResetToken = await prisma.passwordResetToken.createMany({
     *   data: [
     *     // ... provide data here
     *   ]
     * })
     *     
     */
    createMany<T extends PasswordResetTokenCreateManyArgs>(args?: SelectSubset<T, PasswordResetTokenCreateManyArgs<ExtArgs>>): Prisma.PrismaPromise<BatchPayload>

    /**
     * Create many PasswordResetTokens and returns the data saved in the database.
     * @param {PasswordResetTokenCreateManyAndReturnArgs} args - Arguments to create many PasswordResetTokens.
     * @example
     * // Create many PasswordResetTokens
     * const passwordResetToken = await prisma.passwordResetToken.createManyAndReturn({
     *   data: [
     *     // ... provide data here
     *   ]
     * })
     * 
     * // Create many PasswordResetTokens and only return the `id`
     * const passwordResetTokenWithIdOnly = await prisma.passwordResetToken.createManyAndReturn({
     *   select: { id: true },
     *   data: [
     *     // ... provide data here
     *   ]
     * })
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * 
     */
    createManyAndReturn<T extends PasswordResetTokenCreateManyAndReturnArgs>(args?: SelectSubset<T, PasswordResetTokenCreateManyAndReturnArgs<ExtArgs>>): Prisma.PrismaPromise<$Result.GetResult<Prisma.$PasswordResetTokenPayload<ExtArgs>, T, "createManyAndReturn", GlobalOmitOptions>>

    /**
     * Delete a PasswordResetToken.
     * @param {PasswordResetTokenDeleteArgs} args - Arguments to delete one PasswordResetToken.
     * @example
     * // Delete one PasswordResetToken
     * const PasswordResetToken = await prisma.passwordResetToken.delete({
     *   where: {
     *     // ... filter to delete one PasswordResetToken
     *   }
     * })
     * 
     */
    delete<T extends PasswordResetTokenDeleteArgs>(args: SelectSubset<T, PasswordResetTokenDeleteArgs<ExtArgs>>): Prisma__PasswordResetTokenClient<$Result.GetResult<Prisma.$PasswordResetTokenPayload<ExtArgs>, T, "delete", GlobalOmitOptions>, never, ExtArgs, GlobalOmitOptions>

    /**
     * Update one PasswordResetToken.
     * @param {PasswordResetTokenUpdateArgs} args - Arguments to update one PasswordResetToken.
     * @example
     * // Update one PasswordResetToken
     * const passwordResetToken = await prisma.passwordResetToken.update({
     *   where: {
     *     // ... provide filter here
     *   },
     *   data: {
     *     // ... provide data here
     *   }
     * })
     * 
     */
    update<T extends PasswordResetTokenUpdateArgs>(args: SelectSubset<T, PasswordResetTokenUpdateArgs<ExtArgs>>): Prisma__PasswordResetTokenClient<$Result.GetResult<Prisma.$PasswordResetTokenPayload<ExtArgs>, T, "update", GlobalOmitOptions>, never, ExtArgs, GlobalOmitOptions>

    /**
     * Delete zero or more PasswordResetTokens.
     * @param {PasswordResetTokenDeleteManyArgs} args - Arguments to filter PasswordResetTokens to delete.
     * @example
     * // Delete a few PasswordResetTokens
     * const { count } = await prisma.passwordResetToken.deleteMany({
     *   where: {
     *     // ... provide filter here
     *   }
     * })
     * 
     */
    deleteMany<T extends PasswordResetTokenDeleteManyArgs>(args?: SelectSubset<T, PasswordResetTokenDeleteManyArgs<ExtArgs>>): Prisma.PrismaPromise<BatchPayload>

    /**
     * Update zero or more PasswordResetTokens.
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * @param {PasswordResetTokenUpdateManyArgs} args - Arguments to update one or more rows.
     * @example
     * // Update many PasswordResetTokens
     * const passwordResetToken = await prisma.passwordResetToken.updateMany({
     *   where: {
     *     // ... provide filter here
     *   },
     *   data: {
     *     // ... provide data here
     *   }
     * })
     * 
     */
    updateMany<T extends PasswordResetTokenUpdateManyArgs>(args: SelectSubset<T, PasswordResetTokenUpdateManyArgs<ExtArgs>>): Prisma.PrismaPromise<BatchPayload>

    /**
     * Update zero or more PasswordResetTokens and returns the data updated in the database.
     * @param {PasswordResetTokenUpdateManyAndReturnArgs} args - Arguments to update many PasswordResetTokens.
     * @example
     * // Update many PasswordResetTokens
     * const passwordResetToken = await prisma.passwordResetToken.updateManyAndReturn({
     *   where: {
     *     // ... provide filter here
     *   },
     *   data: [
     *     // ... provide data here
     *   ]
     * })
     * 
     * // Update zero or more PasswordResetTokens and only return the `id`
     * const passwordResetTokenWithIdOnly = await prisma.passwordResetToken.updateManyAndReturn({
     *   select: { id: true },
     *   where: {
     *     // ... provide filter here
     *   },
     *   data: [
     *     // ... provide data here
     *   ]
     * })
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * 
     */
    updateManyAndReturn<T extends PasswordResetTokenUpdateManyAndReturnArgs>(args: SelectSubset<T, PasswordResetTokenUpdateManyAndReturnArgs<ExtArgs>>): Prisma.PrismaPromise<$Result.GetResult<Prisma.$PasswordResetTokenPayload<ExtArgs>, T, "updateManyAndReturn", GlobalOmitOptions>>

    /**
     * Create or update one PasswordResetToken.
     * @param {PasswordResetTokenUpsertArgs} args - Arguments to update or create a PasswordResetToken.
     * @example
     * // Update or create a PasswordResetToken
     * const passwordResetToken = await prisma.passwordResetToken.upsert({
     *   create: {
     *     // ... data to create a PasswordResetToken
     *   },
     *   update: {
     *     // ... in case it already exists, update
     *   },
     *   where: {
     *     // ... the filter for the PasswordResetToken we want to update
     *   }
     * })
     */
    upsert<T extends PasswordResetTokenUpsertArgs>(args: SelectSubset<T, PasswordResetTokenUpsertArgs<ExtArgs>>): Prisma__PasswordResetTokenClient<$Result.GetResult<Prisma.$PasswordResetTokenPayload<ExtArgs>, T, "upsert", GlobalOmitOptions>, never, ExtArgs, GlobalOmitOptions>


    /**
     * Count the number of PasswordResetTokens.
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * @param {PasswordResetTokenCountArgs} args - Arguments to filter PasswordResetTokens to count.
     * @example
     * // Count the number of PasswordResetTokens
     * const count = await prisma.passwordResetToken.count({
     *   where: {
     *     // ... the filter for the PasswordResetTokens we want to count
     *   }
     * })
    **/
    count<T extends PasswordResetTokenCountArgs>(
      args?: Subset<T, PasswordResetTokenCountArgs>,
    ): Prisma.PrismaPromise<
      T extends $Utils.Record<'select', any>
        ? T['select'] extends true
          ? number
          : GetScalarType<T['select'], PasswordResetTokenCountAggregateOutputType>
        : number
    >

    /**
     * Allows you to perform aggregations operations on a PasswordResetToken.
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * @param {PasswordResetTokenAggregateArgs} args - Select which aggregations you would like to apply and on what fields.
     * @example
     * // Ordered by age ascending
     * // Where email contains prisma.io
     * // Limited to the 10 users
     * const aggregations = await prisma.user.aggregate({
     *   _avg: {
     *     age: true,
     *   },
     *   where: {
     *     email: {
     *       contains: "prisma.io",
     *     },
     *   },
     *   orderBy: {
     *     age: "asc",
     *   },
     *   take: 10,
     * })
    **/
    aggregate<T extends PasswordResetTokenAggregateArgs>(args: Subset<T, PasswordResetTokenAggregateArgs>): Prisma.PrismaPromise<GetPasswordResetTokenAggregateType<T>>

    /**
     * Group by PasswordResetToken.
     * Note, that providing `undefined` is treated as the value not being there.
     * Read more here: https://pris.ly/d/null-undefined
     * @param {PasswordResetTokenGroupByArgs} args - Group by arguments.
     * @example
     * // Group by city, order by createdAt, get count
     * const result = await prisma.user.groupBy({
     *   by: ['city', 'createdAt'],
     *   orderBy: {
     *     createdAt: true
     *   },
     *   _count: {
     *     _all: true
     *   },
     * })
     * 
    **/
    groupBy<
      T extends PasswordResetTokenGroupByArgs,
      HasSelectOrTake extends Or<
        Extends<'skip', Keys<T>>,
        Extends<'take', Keys<T>>
      >,
      OrderByArg extends True extends HasSelectOrTake
        ? { orderBy: PasswordResetTokenGroupByArgs['orderBy'] }
        : { orderBy?: PasswordResetTokenGroupByArgs['orderBy'] },
      OrderFields extends ExcludeUnderscoreKeys<Keys<MaybeTupleToUnion<T['orderBy']>>>,
      ByFields extends MaybeTupleToUnion<T['by']>,
      ByValid extends Has<ByFields, OrderFields>,
      HavingFields extends GetHavingFields<T['having']>,
      HavingValid extends Has<ByFields, HavingFields>,
      ByEmpty extends T['by'] extends never[] ? True : False,
      InputErrors extends ByEmpty extends True
      ? `Error: "by" must not be empty.`
      : HavingValid extends False
      ? {
          [P in HavingFields]: P extends ByFields
            ? never
            : P extends string
            ? `Error: Field "${P}" used in "having" needs to be provided in "by".`
            : [
                Error,
                'Field ',
                P,
                ` in "having" needs to be provided in "by"`,
              ]
        }[HavingFields]
      : 'take' extends Keys<T>
      ? 'orderBy' extends Keys<T>
        ? ByValid extends True
          ? {}
          : {
              [P in OrderFields]: P extends ByFields
                ? never
                : `Error: Field "${P}" in "orderBy" needs to be provided in "by"`
            }[OrderFields]
        : 'Error: If you provide "take", you also need to provide "orderBy"'
      : 'skip' extends Keys<T>
      ? 'orderBy' extends Keys<T>
        ? ByValid extends True
          ? {}
          : {
              [P in OrderFields]: P extends ByFields
                ? never
                : `Error: Field "${P}" in "orderBy" needs to be provided in "by"`
            }[OrderFields]
        : 'Error: If you provide "skip", you also need to provide "orderBy"'
      : ByValid extends True
      ? {}
      : {
          [P in OrderFields]: P extends ByFields
            ? never
            : `Error: Field "${P}" in "orderBy" needs to be provided in "by"`
        }[OrderFields]
    >(args: SubsetIntersection<T, PasswordResetTokenGroupByArgs, OrderByArg> & InputErrors): {} extends InputErrors ? GetPasswordResetTokenGroupByPayload<T> : Prisma.PrismaPromise<InputErrors>
  /**
   * Fields of the PasswordResetToken model
   */
  readonly fields: PasswordResetTokenFieldRefs;
  }

  /**
   * The delegate class that acts as a "Promise-like" for PasswordResetToken.
   * Why is this prefixed with `Prisma__`?
   * Because we want to prevent naming conflicts as mentioned in
   * https://github.com/prisma/prisma-client-js/issues/707
   */
  export interface Prisma__PasswordResetTokenClient<T, Null = never, ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs, GlobalOmitOptions = {}> extends Prisma.PrismaPromise<T> {
    readonly [Symbol.toStringTag]: "PrismaPromise"
    user<T extends UsersDefaultArgs<ExtArgs> = {}>(args?: Subset<T, UsersDefaultArgs<ExtArgs>>): Prisma__UsersClient<$Result.GetResult<Prisma.$UsersPayload<ExtArgs>, T, "findUniqueOrThrow", GlobalOmitOptions> | Null, Null, ExtArgs, GlobalOmitOptions>
    /**
     * Attaches callbacks for the resolution and/or rejection of the Promise.
     * @param onfulfilled The callback to execute when the Promise is resolved.
     * @param onrejected The callback to execute when the Promise is rejected.
     * @returns A Promise for the completion of which ever callback is executed.
     */
    then<TResult1 = T, TResult2 = never>(onfulfilled?: ((value: T) => TResult1 | PromiseLike<TResult1>) | undefined | null, onrejected?: ((reason: any) => TResult2 | PromiseLike<TResult2>) | undefined | null): $Utils.JsPromise<TResult1 | TResult2>
    /**
     * Attaches a callback for only the rejection of the Promise.
     * @param onrejected The callback to execute when the Promise is rejected.
     * @returns A Promise for the completion of the callback.
     */
    catch<TResult = never>(onrejected?: ((reason: any) => TResult | PromiseLike<TResult>) | undefined | null): $Utils.JsPromise<T | TResult>
    /**
     * Attaches a callback that is invoked when the Promise is settled (fulfilled or rejected). The
     * resolved value cannot be modified from the callback.
     * @param onfinally The callback to execute when the Promise is settled (fulfilled or rejected).
     * @returns A Promise for the completion of the callback.
     */
    finally(onfinally?: (() => void) | undefined | null): $Utils.JsPromise<T>
  }




  /**
   * Fields of the PasswordResetToken model
   */
  interface PasswordResetTokenFieldRefs {
    readonly id: FieldRef<"PasswordResetToken", 'Int'>
    readonly token: FieldRef<"PasswordResetToken", 'String'>
    readonly userId: FieldRef<"PasswordResetToken", 'Int'>
    readonly expiresAt: FieldRef<"PasswordResetToken", 'DateTime'>
    readonly createdAt: FieldRef<"PasswordResetToken", 'DateTime'>
  }
    

  // Custom InputTypes
  /**
   * PasswordResetToken findUnique
   */
  export type PasswordResetTokenFindUniqueArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the PasswordResetToken
     */
    select?: PasswordResetTokenSelect<ExtArgs> | null
    /**
     * Omit specific fields from the PasswordResetToken
     */
    omit?: PasswordResetTokenOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: PasswordResetTokenInclude<ExtArgs> | null
    /**
     * Filter, which PasswordResetToken to fetch.
     */
    where: PasswordResetTokenWhereUniqueInput
  }

  /**
   * PasswordResetToken findUniqueOrThrow
   */
  export type PasswordResetTokenFindUniqueOrThrowArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the PasswordResetToken
     */
    select?: PasswordResetTokenSelect<ExtArgs> | null
    /**
     * Omit specific fields from the PasswordResetToken
     */
    omit?: PasswordResetTokenOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: PasswordResetTokenInclude<ExtArgs> | null
    /**
     * Filter, which PasswordResetToken to fetch.
     */
    where: PasswordResetTokenWhereUniqueInput
  }

  /**
   * PasswordResetToken findFirst
   */
  export type PasswordResetTokenFindFirstArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the PasswordResetToken
     */
    select?: PasswordResetTokenSelect<ExtArgs> | null
    /**
     * Omit specific fields from the PasswordResetToken
     */
    omit?: PasswordResetTokenOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: PasswordResetTokenInclude<ExtArgs> | null
    /**
     * Filter, which PasswordResetToken to fetch.
     */
    where?: PasswordResetTokenWhereInput
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/sorting Sorting Docs}
     * 
     * Determine the order of PasswordResetTokens to fetch.
     */
    orderBy?: PasswordResetTokenOrderByWithRelationInput | PasswordResetTokenOrderByWithRelationInput[]
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination#cursor-based-pagination Cursor Docs}
     * 
     * Sets the position for searching for PasswordResetTokens.
     */
    cursor?: PasswordResetTokenWhereUniqueInput
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination Pagination Docs}
     * 
     * Take `±n` PasswordResetTokens from the position of the cursor.
     */
    take?: number
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination Pagination Docs}
     * 
     * Skip the first `n` PasswordResetTokens.
     */
    skip?: number
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/distinct Distinct Docs}
     * 
     * Filter by unique combinations of PasswordResetTokens.
     */
    distinct?: PasswordResetTokenScalarFieldEnum | PasswordResetTokenScalarFieldEnum[]
  }

  /**
   * PasswordResetToken findFirstOrThrow
   */
  export type PasswordResetTokenFindFirstOrThrowArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the PasswordResetToken
     */
    select?: PasswordResetTokenSelect<ExtArgs> | null
    /**
     * Omit specific fields from the PasswordResetToken
     */
    omit?: PasswordResetTokenOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: PasswordResetTokenInclude<ExtArgs> | null
    /**
     * Filter, which PasswordResetToken to fetch.
     */
    where?: PasswordResetTokenWhereInput
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/sorting Sorting Docs}
     * 
     * Determine the order of PasswordResetTokens to fetch.
     */
    orderBy?: PasswordResetTokenOrderByWithRelationInput | PasswordResetTokenOrderByWithRelationInput[]
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination#cursor-based-pagination Cursor Docs}
     * 
     * Sets the position for searching for PasswordResetTokens.
     */
    cursor?: PasswordResetTokenWhereUniqueInput
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination Pagination Docs}
     * 
     * Take `±n` PasswordResetTokens from the position of the cursor.
     */
    take?: number
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination Pagination Docs}
     * 
     * Skip the first `n` PasswordResetTokens.
     */
    skip?: number
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/distinct Distinct Docs}
     * 
     * Filter by unique combinations of PasswordResetTokens.
     */
    distinct?: PasswordResetTokenScalarFieldEnum | PasswordResetTokenScalarFieldEnum[]
  }

  /**
   * PasswordResetToken findMany
   */
  export type PasswordResetTokenFindManyArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the PasswordResetToken
     */
    select?: PasswordResetTokenSelect<ExtArgs> | null
    /**
     * Omit specific fields from the PasswordResetToken
     */
    omit?: PasswordResetTokenOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: PasswordResetTokenInclude<ExtArgs> | null
    /**
     * Filter, which PasswordResetTokens to fetch.
     */
    where?: PasswordResetTokenWhereInput
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/sorting Sorting Docs}
     * 
     * Determine the order of PasswordResetTokens to fetch.
     */
    orderBy?: PasswordResetTokenOrderByWithRelationInput | PasswordResetTokenOrderByWithRelationInput[]
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination#cursor-based-pagination Cursor Docs}
     * 
     * Sets the position for listing PasswordResetTokens.
     */
    cursor?: PasswordResetTokenWhereUniqueInput
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination Pagination Docs}
     * 
     * Take `±n` PasswordResetTokens from the position of the cursor.
     */
    take?: number
    /**
     * {@link https://www.prisma.io/docs/concepts/components/prisma-client/pagination Pagination Docs}
     * 
     * Skip the first `n` PasswordResetTokens.
     */
    skip?: number
    distinct?: PasswordResetTokenScalarFieldEnum | PasswordResetTokenScalarFieldEnum[]
  }

  /**
   * PasswordResetToken create
   */
  export type PasswordResetTokenCreateArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the PasswordResetToken
     */
    select?: PasswordResetTokenSelect<ExtArgs> | null
    /**
     * Omit specific fields from the PasswordResetToken
     */
    omit?: PasswordResetTokenOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: PasswordResetTokenInclude<ExtArgs> | null
    /**
     * The data needed to create a PasswordResetToken.
     */
    data: XOR<PasswordResetTokenCreateInput, PasswordResetTokenUncheckedCreateInput>
  }

  /**
   * PasswordResetToken createMany
   */
  export type PasswordResetTokenCreateManyArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * The data used to create many PasswordResetTokens.
     */
    data: PasswordResetTokenCreateManyInput | PasswordResetTokenCreateManyInput[]
    skipDuplicates?: boolean
  }

  /**
   * PasswordResetToken createManyAndReturn
   */
  export type PasswordResetTokenCreateManyAndReturnArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the PasswordResetToken
     */
    select?: PasswordResetTokenSelectCreateManyAndReturn<ExtArgs> | null
    /**
     * Omit specific fields from the PasswordResetToken
     */
    omit?: PasswordResetTokenOmit<ExtArgs> | null
    /**
     * The data used to create many PasswordResetTokens.
     */
    data: PasswordResetTokenCreateManyInput | PasswordResetTokenCreateManyInput[]
    skipDuplicates?: boolean
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: PasswordResetTokenIncludeCreateManyAndReturn<ExtArgs> | null
  }

  /**
   * PasswordResetToken update
   */
  export type PasswordResetTokenUpdateArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the PasswordResetToken
     */
    select?: PasswordResetTokenSelect<ExtArgs> | null
    /**
     * Omit specific fields from the PasswordResetToken
     */
    omit?: PasswordResetTokenOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: PasswordResetTokenInclude<ExtArgs> | null
    /**
     * The data needed to update a PasswordResetToken.
     */
    data: XOR<PasswordResetTokenUpdateInput, PasswordResetTokenUncheckedUpdateInput>
    /**
     * Choose, which PasswordResetToken to update.
     */
    where: PasswordResetTokenWhereUniqueInput
  }

  /**
   * PasswordResetToken updateMany
   */
  export type PasswordResetTokenUpdateManyArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * The data used to update PasswordResetTokens.
     */
    data: XOR<PasswordResetTokenUpdateManyMutationInput, PasswordResetTokenUncheckedUpdateManyInput>
    /**
     * Filter which PasswordResetTokens to update
     */
    where?: PasswordResetTokenWhereInput
    /**
     * Limit how many PasswordResetTokens to update.
     */
    limit?: number
  }

  /**
   * PasswordResetToken updateManyAndReturn
   */
  export type PasswordResetTokenUpdateManyAndReturnArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the PasswordResetToken
     */
    select?: PasswordResetTokenSelectUpdateManyAndReturn<ExtArgs> | null
    /**
     * Omit specific fields from the PasswordResetToken
     */
    omit?: PasswordResetTokenOmit<ExtArgs> | null
    /**
     * The data used to update PasswordResetTokens.
     */
    data: XOR<PasswordResetTokenUpdateManyMutationInput, PasswordResetTokenUncheckedUpdateManyInput>
    /**
     * Filter which PasswordResetTokens to update
     */
    where?: PasswordResetTokenWhereInput
    /**
     * Limit how many PasswordResetTokens to update.
     */
    limit?: number
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: PasswordResetTokenIncludeUpdateManyAndReturn<ExtArgs> | null
  }

  /**
   * PasswordResetToken upsert
   */
  export type PasswordResetTokenUpsertArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the PasswordResetToken
     */
    select?: PasswordResetTokenSelect<ExtArgs> | null
    /**
     * Omit specific fields from the PasswordResetToken
     */
    omit?: PasswordResetTokenOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: PasswordResetTokenInclude<ExtArgs> | null
    /**
     * The filter to search for the PasswordResetToken to update in case it exists.
     */
    where: PasswordResetTokenWhereUniqueInput
    /**
     * In case the PasswordResetToken found by the `where` argument doesn't exist, create a new PasswordResetToken with this data.
     */
    create: XOR<PasswordResetTokenCreateInput, PasswordResetTokenUncheckedCreateInput>
    /**
     * In case the PasswordResetToken was found with the provided `where` argument, update it with this data.
     */
    update: XOR<PasswordResetTokenUpdateInput, PasswordResetTokenUncheckedUpdateInput>
  }

  /**
   * PasswordResetToken delete
   */
  export type PasswordResetTokenDeleteArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the PasswordResetToken
     */
    select?: PasswordResetTokenSelect<ExtArgs> | null
    /**
     * Omit specific fields from the PasswordResetToken
     */
    omit?: PasswordResetTokenOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: PasswordResetTokenInclude<ExtArgs> | null
    /**
     * Filter which PasswordResetToken to delete.
     */
    where: PasswordResetTokenWhereUniqueInput
  }

  /**
   * PasswordResetToken deleteMany
   */
  export type PasswordResetTokenDeleteManyArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Filter which PasswordResetTokens to delete
     */
    where?: PasswordResetTokenWhereInput
    /**
     * Limit how many PasswordResetTokens to delete.
     */
    limit?: number
  }

  /**
   * PasswordResetToken without action
   */
  export type PasswordResetTokenDefaultArgs<ExtArgs extends $Extensions.InternalArgs = $Extensions.DefaultArgs> = {
    /**
     * Select specific fields to fetch from the PasswordResetToken
     */
    select?: PasswordResetTokenSelect<ExtArgs> | null
    /**
     * Omit specific fields from the PasswordResetToken
     */
    omit?: PasswordResetTokenOmit<ExtArgs> | null
    /**
     * Choose, which related nodes to fetch as well
     */
    include?: PasswordResetTokenInclude<ExtArgs> | null
  }


  /**
   * Enums
   */

  export const TransactionIsolationLevel: {
    ReadUncommitted: 'ReadUncommitted',
    ReadCommitted: 'ReadCommitted',
    RepeatableRead: 'RepeatableRead',
    Serializable: 'Serializable'
  };

  export type TransactionIsolationLevel = (typeof TransactionIsolationLevel)[keyof typeof TransactionIsolationLevel]


  export const UsersScalarFieldEnum: {
    id: 'id',
    name: 'name',
    email: 'email',
    password: 'password',
    isVerified: 'isVerified',
    createdAt: 'createdAt',
    updatedAt: 'updatedAt',
    verificationCode: 'verificationCode',
    verificationCodeExpiration: 'verificationCodeExpiration',
    lastVerificationRequest: 'lastVerificationRequest',
    role: 'role',
    comunicacaocomejaca: 'comunicacaocomejaca',
    comunicacaomovimento: 'comunicacaomovimento',
    telefone: 'telefone',
    resetTokenVersion: 'resetTokenVersion'
  };

  export type UsersScalarFieldEnum = (typeof UsersScalarFieldEnum)[keyof typeof UsersScalarFieldEnum]


  export const InstituicaoEspiritaScalarFieldEnum: {
    id: 'id',
    nome: 'nome',
    nome_CNPJ: 'nome_CNPJ',
    estado: 'estado',
    cidade: 'cidade',
    bairro: 'bairro',
    logradouro: 'logradouro',
    numero: 'numero',
    complemento: 'complemento',
    telefone: 'telefone',
    email: 'email',
    createdAt: 'createdAt',
    updatedAt: 'updatedAt',
    criadoPorId: 'criadoPorId',
    sigla: 'sigla',
    CEU: 'CEU',
    dia: 'dia',
    horario: 'horario',
    atualizadoPorId: 'atualizadoPorId',
    CNPJ: 'CNPJ'
  };

  export type InstituicaoEspiritaScalarFieldEnum = (typeof InstituicaoEspiritaScalarFieldEnum)[keyof typeof InstituicaoEspiritaScalarFieldEnum]


  export const Participante2025ScalarFieldEnum: {
    id: 'id',
    nomeCompleto: 'nomeCompleto',
    nomeCracha: 'nomeCracha',
    cpf: 'cpf',
    nomeSocial: 'nomeSocial',
    dataNascimento: 'dataNascimento',
    sexo: 'sexo',
    email: 'email',
    telefone: 'telefone',
    nomeCompletoResponsavel: 'nomeCompletoResponsavel',
    documentoResponsavel: 'documentoResponsavel',
    telefoneResponsavel: 'telefoneResponsavel',
    linkPagamento: 'linkPagamento',
    idade: 'idade',
    valor: 'valor',
    statusPagamento: 'statusPagamento',
    tipoParticipacao: 'tipoParticipacao',
    comissao: 'comissao',
    tamanhoCamisa: 'tamanhoCamisa',
    cep: 'cep',
    estado: 'estado',
    cidade: 'cidade',
    bairro: 'bairro',
    logradouro: 'logradouro',
    numero: 'numero',
    complemento: 'complemento',
    outroGenero: 'outroGenero',
    medicacao: 'medicacao',
    alergia: 'alergia',
    outrasInformacoes: 'outrasInformacoes',
    userId: 'userId',
    createdAt: 'createdAt',
    updatedAt: 'updatedAt',
    IE: 'IE',
    instituicaoId: 'instituicaoId',
    vegetariano: 'vegetariano',
    camisa: 'camisa',
    primeiraComejaca: 'primeiraComejaca',
    deficienciaAuditiva: 'deficienciaAuditiva',
    deficienciaAutismo: 'deficienciaAutismo',
    deficienciaIntelectual: 'deficienciaIntelectual',
    deficienciaParalisiaCerebral: 'deficienciaParalisiaCerebral',
    deficienciaVisual: 'deficienciaVisual',
    deficienciaFisica: 'deficienciaFisica',
    deficienciaOutra: 'deficienciaOutra',
    deficienciaOutraDescricao: 'deficienciaOutraDescricao',
    otherInstitution: 'otherInstitution'
  };

  export type Participante2025ScalarFieldEnum = (typeof Participante2025ScalarFieldEnum)[keyof typeof Participante2025ScalarFieldEnum]


  export const PasswordResetTokenScalarFieldEnum: {
    id: 'id',
    token: 'token',
    userId: 'userId',
    expiresAt: 'expiresAt',
    createdAt: 'createdAt'
  };

  export type PasswordResetTokenScalarFieldEnum = (typeof PasswordResetTokenScalarFieldEnum)[keyof typeof PasswordResetTokenScalarFieldEnum]


  export const SortOrder: {
    asc: 'asc',
    desc: 'desc'
  };

  export type SortOrder = (typeof SortOrder)[keyof typeof SortOrder]


  export const QueryMode: {
    default: 'default',
    insensitive: 'insensitive'
  };

  export type QueryMode = (typeof QueryMode)[keyof typeof QueryMode]


  export const NullsOrder: {
    first: 'first',
    last: 'last'
  };

  export type NullsOrder = (typeof NullsOrder)[keyof typeof NullsOrder]


  /**
   * Field references
   */


  /**
   * Reference to a field of type 'Int'
   */
  export type IntFieldRefInput<$PrismaModel> = FieldRefInputType<$PrismaModel, 'Int'>
    


  /**
   * Reference to a field of type 'Int[]'
   */
  export type ListIntFieldRefInput<$PrismaModel> = FieldRefInputType<$PrismaModel, 'Int[]'>
    


  /**
   * Reference to a field of type 'String'
   */
  export type StringFieldRefInput<$PrismaModel> = FieldRefInputType<$PrismaModel, 'String'>
    


  /**
   * Reference to a field of type 'String[]'
   */
  export type ListStringFieldRefInput<$PrismaModel> = FieldRefInputType<$PrismaModel, 'String[]'>
    


  /**
   * Reference to a field of type 'Boolean'
   */
  export type BooleanFieldRefInput<$PrismaModel> = FieldRefInputType<$PrismaModel, 'Boolean'>
    


  /**
   * Reference to a field of type 'DateTime'
   */
  export type DateTimeFieldRefInput<$PrismaModel> = FieldRefInputType<$PrismaModel, 'DateTime'>
    


  /**
   * Reference to a field of type 'DateTime[]'
   */
  export type ListDateTimeFieldRefInput<$PrismaModel> = FieldRefInputType<$PrismaModel, 'DateTime[]'>
    


  /**
   * Reference to a field of type 'Role'
   */
  export type EnumRoleFieldRefInput<$PrismaModel> = FieldRefInputType<$PrismaModel, 'Role'>
    


  /**
   * Reference to a field of type 'Role[]'
   */
  export type ListEnumRoleFieldRefInput<$PrismaModel> = FieldRefInputType<$PrismaModel, 'Role[]'>
    


  /**
   * Reference to a field of type 'Float'
   */
  export type FloatFieldRefInput<$PrismaModel> = FieldRefInputType<$PrismaModel, 'Float'>
    


  /**
   * Reference to a field of type 'Float[]'
   */
  export type ListFloatFieldRefInput<$PrismaModel> = FieldRefInputType<$PrismaModel, 'Float[]'>
    


  /**
   * Reference to a field of type 'TipoParticipacao'
   */
  export type EnumTipoParticipacaoFieldRefInput<$PrismaModel> = FieldRefInputType<$PrismaModel, 'TipoParticipacao'>
    


  /**
   * Reference to a field of type 'TipoParticipacao[]'
   */
  export type ListEnumTipoParticipacaoFieldRefInput<$PrismaModel> = FieldRefInputType<$PrismaModel, 'TipoParticipacao[]'>
    
  /**
   * Deep Input Types
   */


  export type UsersWhereInput = {
    AND?: UsersWhereInput | UsersWhereInput[]
    OR?: UsersWhereInput[]
    NOT?: UsersWhereInput | UsersWhereInput[]
    id?: IntFilter<"Users"> | number
    name?: StringFilter<"Users"> | string
    email?: StringFilter<"Users"> | string
    password?: StringFilter<"Users"> | string
    isVerified?: BoolFilter<"Users"> | boolean
    createdAt?: DateTimeFilter<"Users"> | Date | string
    updatedAt?: DateTimeFilter<"Users"> | Date | string
    verificationCode?: StringNullableFilter<"Users"> | string | null
    verificationCodeExpiration?: DateTimeNullableFilter<"Users"> | Date | string | null
    lastVerificationRequest?: DateTimeFilter<"Users"> | Date | string
    role?: EnumRoleFilter<"Users"> | $Enums.Role
    comunicacaocomejaca?: StringNullableFilter<"Users"> | string | null
    comunicacaomovimento?: StringNullableFilter<"Users"> | string | null
    telefone?: StringNullableFilter<"Users"> | string | null
    resetTokenVersion?: IntFilter<"Users"> | number
    instituicoesAtualizadas?: InstituicaoEspiritaListRelationFilter
    instituicoesCriadas?: InstituicaoEspiritaListRelationFilter
    Participante2025?: Participante2025ListRelationFilter
    instituicoes?: InstituicaoEspiritaListRelationFilter
    passwordResetTokens?: PasswordResetTokenListRelationFilter
  }

  export type UsersOrderByWithRelationInput = {
    id?: SortOrder
    name?: SortOrder
    email?: SortOrder
    password?: SortOrder
    isVerified?: SortOrder
    createdAt?: SortOrder
    updatedAt?: SortOrder
    verificationCode?: SortOrderInput | SortOrder
    verificationCodeExpiration?: SortOrderInput | SortOrder
    lastVerificationRequest?: SortOrder
    role?: SortOrder
    comunicacaocomejaca?: SortOrderInput | SortOrder
    comunicacaomovimento?: SortOrderInput | SortOrder
    telefone?: SortOrderInput | SortOrder
    resetTokenVersion?: SortOrder
    instituicoesAtualizadas?: InstituicaoEspiritaOrderByRelationAggregateInput
    instituicoesCriadas?: InstituicaoEspiritaOrderByRelationAggregateInput
    Participante2025?: Participante2025OrderByRelationAggregateInput
    instituicoes?: InstituicaoEspiritaOrderByRelationAggregateInput
    passwordResetTokens?: PasswordResetTokenOrderByRelationAggregateInput
  }

  export type UsersWhereUniqueInput = Prisma.AtLeast<{
    id?: number
    email?: string
    AND?: UsersWhereInput | UsersWhereInput[]
    OR?: UsersWhereInput[]
    NOT?: UsersWhereInput | UsersWhereInput[]
    name?: StringFilter<"Users"> | string
    password?: StringFilter<"Users"> | string
    isVerified?: BoolFilter<"Users"> | boolean
    createdAt?: DateTimeFilter<"Users"> | Date | string
    updatedAt?: DateTimeFilter<"Users"> | Date | string
    verificationCode?: StringNullableFilter<"Users"> | string | null
    verificationCodeExpiration?: DateTimeNullableFilter<"Users"> | Date | string | null
    lastVerificationRequest?: DateTimeFilter<"Users"> | Date | string
    role?: EnumRoleFilter<"Users"> | $Enums.Role
    comunicacaocomejaca?: StringNullableFilter<"Users"> | string | null
    comunicacaomovimento?: StringNullableFilter<"Users"> | string | null
    telefone?: StringNullableFilter<"Users"> | string | null
    resetTokenVersion?: IntFilter<"Users"> | number
    instituicoesAtualizadas?: InstituicaoEspiritaListRelationFilter
    instituicoesCriadas?: InstituicaoEspiritaListRelationFilter
    Participante2025?: Participante2025ListRelationFilter
    instituicoes?: InstituicaoEspiritaListRelationFilter
    passwordResetTokens?: PasswordResetTokenListRelationFilter
  }, "id" | "email">

  export type UsersOrderByWithAggregationInput = {
    id?: SortOrder
    name?: SortOrder
    email?: SortOrder
    password?: SortOrder
    isVerified?: SortOrder
    createdAt?: SortOrder
    updatedAt?: SortOrder
    verificationCode?: SortOrderInput | SortOrder
    verificationCodeExpiration?: SortOrderInput | SortOrder
    lastVerificationRequest?: SortOrder
    role?: SortOrder
    comunicacaocomejaca?: SortOrderInput | SortOrder
    comunicacaomovimento?: SortOrderInput | SortOrder
    telefone?: SortOrderInput | SortOrder
    resetTokenVersion?: SortOrder
    _count?: UsersCountOrderByAggregateInput
    _avg?: UsersAvgOrderByAggregateInput
    _max?: UsersMaxOrderByAggregateInput
    _min?: UsersMinOrderByAggregateInput
    _sum?: UsersSumOrderByAggregateInput
  }

  export type UsersScalarWhereWithAggregatesInput = {
    AND?: UsersScalarWhereWithAggregatesInput | UsersScalarWhereWithAggregatesInput[]
    OR?: UsersScalarWhereWithAggregatesInput[]
    NOT?: UsersScalarWhereWithAggregatesInput | UsersScalarWhereWithAggregatesInput[]
    id?: IntWithAggregatesFilter<"Users"> | number
    name?: StringWithAggregatesFilter<"Users"> | string
    email?: StringWithAggregatesFilter<"Users"> | string
    password?: StringWithAggregatesFilter<"Users"> | string
    isVerified?: BoolWithAggregatesFilter<"Users"> | boolean
    createdAt?: DateTimeWithAggregatesFilter<"Users"> | Date | string
    updatedAt?: DateTimeWithAggregatesFilter<"Users"> | Date | string
    verificationCode?: StringNullableWithAggregatesFilter<"Users"> | string | null
    verificationCodeExpiration?: DateTimeNullableWithAggregatesFilter<"Users"> | Date | string | null
    lastVerificationRequest?: DateTimeWithAggregatesFilter<"Users"> | Date | string
    role?: EnumRoleWithAggregatesFilter<"Users"> | $Enums.Role
    comunicacaocomejaca?: StringNullableWithAggregatesFilter<"Users"> | string | null
    comunicacaomovimento?: StringNullableWithAggregatesFilter<"Users"> | string | null
    telefone?: StringNullableWithAggregatesFilter<"Users"> | string | null
    resetTokenVersion?: IntWithAggregatesFilter<"Users"> | number
  }

  export type InstituicaoEspiritaWhereInput = {
    AND?: InstituicaoEspiritaWhereInput | InstituicaoEspiritaWhereInput[]
    OR?: InstituicaoEspiritaWhereInput[]
    NOT?: InstituicaoEspiritaWhereInput | InstituicaoEspiritaWhereInput[]
    id?: IntFilter<"InstituicaoEspirita"> | number
    nome?: StringFilter<"InstituicaoEspirita"> | string
    nome_CNPJ?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    estado?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    cidade?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    bairro?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    logradouro?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    numero?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    complemento?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    telefone?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    email?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    createdAt?: DateTimeFilter<"InstituicaoEspirita"> | Date | string
    updatedAt?: DateTimeFilter<"InstituicaoEspirita"> | Date | string
    criadoPorId?: IntNullableFilter<"InstituicaoEspirita"> | number | null
    sigla?: StringFilter<"InstituicaoEspirita"> | string
    CEU?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    dia?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    horario?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    atualizadoPorId?: IntNullableFilter<"InstituicaoEspirita"> | number | null
    CNPJ?: StringFilter<"InstituicaoEspirita"> | string
    atualizadoPor?: XOR<UsersNullableScalarRelationFilter, UsersWhereInput> | null
    criadoPor?: XOR<UsersNullableScalarRelationFilter, UsersWhereInput> | null
    Participante2025?: Participante2025ListRelationFilter
    Users?: UsersListRelationFilter
  }

  export type InstituicaoEspiritaOrderByWithRelationInput = {
    id?: SortOrder
    nome?: SortOrder
    nome_CNPJ?: SortOrderInput | SortOrder
    estado?: SortOrderInput | SortOrder
    cidade?: SortOrderInput | SortOrder
    bairro?: SortOrderInput | SortOrder
    logradouro?: SortOrderInput | SortOrder
    numero?: SortOrderInput | SortOrder
    complemento?: SortOrderInput | SortOrder
    telefone?: SortOrderInput | SortOrder
    email?: SortOrderInput | SortOrder
    createdAt?: SortOrder
    updatedAt?: SortOrder
    criadoPorId?: SortOrderInput | SortOrder
    sigla?: SortOrder
    CEU?: SortOrderInput | SortOrder
    dia?: SortOrderInput | SortOrder
    horario?: SortOrderInput | SortOrder
    atualizadoPorId?: SortOrderInput | SortOrder
    CNPJ?: SortOrder
    atualizadoPor?: UsersOrderByWithRelationInput
    criadoPor?: UsersOrderByWithRelationInput
    Participante2025?: Participante2025OrderByRelationAggregateInput
    Users?: UsersOrderByRelationAggregateInput
  }

  export type InstituicaoEspiritaWhereUniqueInput = Prisma.AtLeast<{
    id?: number
    CNPJ?: string
    AND?: InstituicaoEspiritaWhereInput | InstituicaoEspiritaWhereInput[]
    OR?: InstituicaoEspiritaWhereInput[]
    NOT?: InstituicaoEspiritaWhereInput | InstituicaoEspiritaWhereInput[]
    nome?: StringFilter<"InstituicaoEspirita"> | string
    nome_CNPJ?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    estado?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    cidade?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    bairro?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    logradouro?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    numero?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    complemento?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    telefone?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    email?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    createdAt?: DateTimeFilter<"InstituicaoEspirita"> | Date | string
    updatedAt?: DateTimeFilter<"InstituicaoEspirita"> | Date | string
    criadoPorId?: IntNullableFilter<"InstituicaoEspirita"> | number | null
    sigla?: StringFilter<"InstituicaoEspirita"> | string
    CEU?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    dia?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    horario?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    atualizadoPorId?: IntNullableFilter<"InstituicaoEspirita"> | number | null
    atualizadoPor?: XOR<UsersNullableScalarRelationFilter, UsersWhereInput> | null
    criadoPor?: XOR<UsersNullableScalarRelationFilter, UsersWhereInput> | null
    Participante2025?: Participante2025ListRelationFilter
    Users?: UsersListRelationFilter
  }, "id" | "CNPJ">

  export type InstituicaoEspiritaOrderByWithAggregationInput = {
    id?: SortOrder
    nome?: SortOrder
    nome_CNPJ?: SortOrderInput | SortOrder
    estado?: SortOrderInput | SortOrder
    cidade?: SortOrderInput | SortOrder
    bairro?: SortOrderInput | SortOrder
    logradouro?: SortOrderInput | SortOrder
    numero?: SortOrderInput | SortOrder
    complemento?: SortOrderInput | SortOrder
    telefone?: SortOrderInput | SortOrder
    email?: SortOrderInput | SortOrder
    createdAt?: SortOrder
    updatedAt?: SortOrder
    criadoPorId?: SortOrderInput | SortOrder
    sigla?: SortOrder
    CEU?: SortOrderInput | SortOrder
    dia?: SortOrderInput | SortOrder
    horario?: SortOrderInput | SortOrder
    atualizadoPorId?: SortOrderInput | SortOrder
    CNPJ?: SortOrder
    _count?: InstituicaoEspiritaCountOrderByAggregateInput
    _avg?: InstituicaoEspiritaAvgOrderByAggregateInput
    _max?: InstituicaoEspiritaMaxOrderByAggregateInput
    _min?: InstituicaoEspiritaMinOrderByAggregateInput
    _sum?: InstituicaoEspiritaSumOrderByAggregateInput
  }

  export type InstituicaoEspiritaScalarWhereWithAggregatesInput = {
    AND?: InstituicaoEspiritaScalarWhereWithAggregatesInput | InstituicaoEspiritaScalarWhereWithAggregatesInput[]
    OR?: InstituicaoEspiritaScalarWhereWithAggregatesInput[]
    NOT?: InstituicaoEspiritaScalarWhereWithAggregatesInput | InstituicaoEspiritaScalarWhereWithAggregatesInput[]
    id?: IntWithAggregatesFilter<"InstituicaoEspirita"> | number
    nome?: StringWithAggregatesFilter<"InstituicaoEspirita"> | string
    nome_CNPJ?: StringNullableWithAggregatesFilter<"InstituicaoEspirita"> | string | null
    estado?: StringNullableWithAggregatesFilter<"InstituicaoEspirita"> | string | null
    cidade?: StringNullableWithAggregatesFilter<"InstituicaoEspirita"> | string | null
    bairro?: StringNullableWithAggregatesFilter<"InstituicaoEspirita"> | string | null
    logradouro?: StringNullableWithAggregatesFilter<"InstituicaoEspirita"> | string | null
    numero?: StringNullableWithAggregatesFilter<"InstituicaoEspirita"> | string | null
    complemento?: StringNullableWithAggregatesFilter<"InstituicaoEspirita"> | string | null
    telefone?: StringNullableWithAggregatesFilter<"InstituicaoEspirita"> | string | null
    email?: StringNullableWithAggregatesFilter<"InstituicaoEspirita"> | string | null
    createdAt?: DateTimeWithAggregatesFilter<"InstituicaoEspirita"> | Date | string
    updatedAt?: DateTimeWithAggregatesFilter<"InstituicaoEspirita"> | Date | string
    criadoPorId?: IntNullableWithAggregatesFilter<"InstituicaoEspirita"> | number | null
    sigla?: StringWithAggregatesFilter<"InstituicaoEspirita"> | string
    CEU?: StringNullableWithAggregatesFilter<"InstituicaoEspirita"> | string | null
    dia?: StringNullableWithAggregatesFilter<"InstituicaoEspirita"> | string | null
    horario?: StringNullableWithAggregatesFilter<"InstituicaoEspirita"> | string | null
    atualizadoPorId?: IntNullableWithAggregatesFilter<"InstituicaoEspirita"> | number | null
    CNPJ?: StringWithAggregatesFilter<"InstituicaoEspirita"> | string
  }

  export type Participante2025WhereInput = {
    AND?: Participante2025WhereInput | Participante2025WhereInput[]
    OR?: Participante2025WhereInput[]
    NOT?: Participante2025WhereInput | Participante2025WhereInput[]
    id?: StringFilter<"Participante2025"> | string
    nomeCompleto?: StringFilter<"Participante2025"> | string
    nomeCracha?: StringNullableFilter<"Participante2025"> | string | null
    cpf?: StringNullableFilter<"Participante2025"> | string | null
    nomeSocial?: StringNullableFilter<"Participante2025"> | string | null
    dataNascimento?: DateTimeFilter<"Participante2025"> | Date | string
    sexo?: StringFilter<"Participante2025"> | string
    email?: StringFilter<"Participante2025"> | string
    telefone?: StringFilter<"Participante2025"> | string
    nomeCompletoResponsavel?: StringNullableFilter<"Participante2025"> | string | null
    documentoResponsavel?: StringNullableFilter<"Participante2025"> | string | null
    telefoneResponsavel?: StringNullableFilter<"Participante2025"> | string | null
    linkPagamento?: StringNullableFilter<"Participante2025"> | string | null
    idade?: IntNullableFilter<"Participante2025"> | number | null
    valor?: FloatNullableFilter<"Participante2025"> | number | null
    statusPagamento?: StringNullableFilter<"Participante2025"> | string | null
    tipoParticipacao?: EnumTipoParticipacaoFilter<"Participante2025"> | $Enums.TipoParticipacao
    comissao?: StringNullableFilter<"Participante2025"> | string | null
    tamanhoCamisa?: StringNullableFilter<"Participante2025"> | string | null
    cep?: StringFilter<"Participante2025"> | string
    estado?: StringNullableFilter<"Participante2025"> | string | null
    cidade?: StringNullableFilter<"Participante2025"> | string | null
    bairro?: StringNullableFilter<"Participante2025"> | string | null
    logradouro?: StringNullableFilter<"Participante2025"> | string | null
    numero?: StringNullableFilter<"Participante2025"> | string | null
    complemento?: StringNullableFilter<"Participante2025"> | string | null
    outroGenero?: StringNullableFilter<"Participante2025"> | string | null
    medicacao?: StringNullableFilter<"Participante2025"> | string | null
    alergia?: StringNullableFilter<"Participante2025"> | string | null
    outrasInformacoes?: StringNullableFilter<"Participante2025"> | string | null
    userId?: IntNullableFilter<"Participante2025"> | number | null
    createdAt?: DateTimeFilter<"Participante2025"> | Date | string
    updatedAt?: DateTimeFilter<"Participante2025"> | Date | string
    IE?: StringFilter<"Participante2025"> | string
    instituicaoId?: IntNullableFilter<"Participante2025"> | number | null
    vegetariano?: StringFilter<"Participante2025"> | string
    camisa?: BoolNullableFilter<"Participante2025"> | boolean | null
    primeiraComejaca?: BoolNullableFilter<"Participante2025"> | boolean | null
    deficienciaAuditiva?: BoolNullableFilter<"Participante2025"> | boolean | null
    deficienciaAutismo?: BoolNullableFilter<"Participante2025"> | boolean | null
    deficienciaIntelectual?: BoolNullableFilter<"Participante2025"> | boolean | null
    deficienciaParalisiaCerebral?: BoolNullableFilter<"Participante2025"> | boolean | null
    deficienciaVisual?: BoolNullableFilter<"Participante2025"> | boolean | null
    deficienciaFisica?: BoolNullableFilter<"Participante2025"> | boolean | null
    deficienciaOutra?: BoolNullableFilter<"Participante2025"> | boolean | null
    deficienciaOutraDescricao?: StringNullableFilter<"Participante2025"> | string | null
    otherInstitution?: StringNullableFilter<"Participante2025"> | string | null
    instituicao?: XOR<InstituicaoEspiritaNullableScalarRelationFilter, InstituicaoEspiritaWhereInput> | null
    user?: XOR<UsersNullableScalarRelationFilter, UsersWhereInput> | null
  }

  export type Participante2025OrderByWithRelationInput = {
    id?: SortOrder
    nomeCompleto?: SortOrder
    nomeCracha?: SortOrderInput | SortOrder
    cpf?: SortOrderInput | SortOrder
    nomeSocial?: SortOrderInput | SortOrder
    dataNascimento?: SortOrder
    sexo?: SortOrder
    email?: SortOrder
    telefone?: SortOrder
    nomeCompletoResponsavel?: SortOrderInput | SortOrder
    documentoResponsavel?: SortOrderInput | SortOrder
    telefoneResponsavel?: SortOrderInput | SortOrder
    linkPagamento?: SortOrderInput | SortOrder
    idade?: SortOrderInput | SortOrder
    valor?: SortOrderInput | SortOrder
    statusPagamento?: SortOrderInput | SortOrder
    tipoParticipacao?: SortOrder
    comissao?: SortOrderInput | SortOrder
    tamanhoCamisa?: SortOrderInput | SortOrder
    cep?: SortOrder
    estado?: SortOrderInput | SortOrder
    cidade?: SortOrderInput | SortOrder
    bairro?: SortOrderInput | SortOrder
    logradouro?: SortOrderInput | SortOrder
    numero?: SortOrderInput | SortOrder
    complemento?: SortOrderInput | SortOrder
    outroGenero?: SortOrderInput | SortOrder
    medicacao?: SortOrderInput | SortOrder
    alergia?: SortOrderInput | SortOrder
    outrasInformacoes?: SortOrderInput | SortOrder
    userId?: SortOrderInput | SortOrder
    createdAt?: SortOrder
    updatedAt?: SortOrder
    IE?: SortOrder
    instituicaoId?: SortOrderInput | SortOrder
    vegetariano?: SortOrder
    camisa?: SortOrderInput | SortOrder
    primeiraComejaca?: SortOrderInput | SortOrder
    deficienciaAuditiva?: SortOrderInput | SortOrder
    deficienciaAutismo?: SortOrderInput | SortOrder
    deficienciaIntelectual?: SortOrderInput | SortOrder
    deficienciaParalisiaCerebral?: SortOrderInput | SortOrder
    deficienciaVisual?: SortOrderInput | SortOrder
    deficienciaFisica?: SortOrderInput | SortOrder
    deficienciaOutra?: SortOrderInput | SortOrder
    deficienciaOutraDescricao?: SortOrderInput | SortOrder
    otherInstitution?: SortOrderInput | SortOrder
    instituicao?: InstituicaoEspiritaOrderByWithRelationInput
    user?: UsersOrderByWithRelationInput
  }

  export type Participante2025WhereUniqueInput = Prisma.AtLeast<{
    id?: string
    AND?: Participante2025WhereInput | Participante2025WhereInput[]
    OR?: Participante2025WhereInput[]
    NOT?: Participante2025WhereInput | Participante2025WhereInput[]
    nomeCompleto?: StringFilter<"Participante2025"> | string
    nomeCracha?: StringNullableFilter<"Participante2025"> | string | null
    cpf?: StringNullableFilter<"Participante2025"> | string | null
    nomeSocial?: StringNullableFilter<"Participante2025"> | string | null
    dataNascimento?: DateTimeFilter<"Participante2025"> | Date | string
    sexo?: StringFilter<"Participante2025"> | string
    email?: StringFilter<"Participante2025"> | string
    telefone?: StringFilter<"Participante2025"> | string
    nomeCompletoResponsavel?: StringNullableFilter<"Participante2025"> | string | null
    documentoResponsavel?: StringNullableFilter<"Participante2025"> | string | null
    telefoneResponsavel?: StringNullableFilter<"Participante2025"> | string | null
    linkPagamento?: StringNullableFilter<"Participante2025"> | string | null
    idade?: IntNullableFilter<"Participante2025"> | number | null
    valor?: FloatNullableFilter<"Participante2025"> | number | null
    statusPagamento?: StringNullableFilter<"Participante2025"> | string | null
    tipoParticipacao?: EnumTipoParticipacaoFilter<"Participante2025"> | $Enums.TipoParticipacao
    comissao?: StringNullableFilter<"Participante2025"> | string | null
    tamanhoCamisa?: StringNullableFilter<"Participante2025"> | string | null
    cep?: StringFilter<"Participante2025"> | string
    estado?: StringNullableFilter<"Participante2025"> | string | null
    cidade?: StringNullableFilter<"Participante2025"> | string | null
    bairro?: StringNullableFilter<"Participante2025"> | string | null
    logradouro?: StringNullableFilter<"Participante2025"> | string | null
    numero?: StringNullableFilter<"Participante2025"> | string | null
    complemento?: StringNullableFilter<"Participante2025"> | string | null
    outroGenero?: StringNullableFilter<"Participante2025"> | string | null
    medicacao?: StringNullableFilter<"Participante2025"> | string | null
    alergia?: StringNullableFilter<"Participante2025"> | string | null
    outrasInformacoes?: StringNullableFilter<"Participante2025"> | string | null
    userId?: IntNullableFilter<"Participante2025"> | number | null
    createdAt?: DateTimeFilter<"Participante2025"> | Date | string
    updatedAt?: DateTimeFilter<"Participante2025"> | Date | string
    IE?: StringFilter<"Participante2025"> | string
    instituicaoId?: IntNullableFilter<"Participante2025"> | number | null
    vegetariano?: StringFilter<"Participante2025"> | string
    camisa?: BoolNullableFilter<"Participante2025"> | boolean | null
    primeiraComejaca?: BoolNullableFilter<"Participante2025"> | boolean | null
    deficienciaAuditiva?: BoolNullableFilter<"Participante2025"> | boolean | null
    deficienciaAutismo?: BoolNullableFilter<"Participante2025"> | boolean | null
    deficienciaIntelectual?: BoolNullableFilter<"Participante2025"> | boolean | null
    deficienciaParalisiaCerebral?: BoolNullableFilter<"Participante2025"> | boolean | null
    deficienciaVisual?: BoolNullableFilter<"Participante2025"> | boolean | null
    deficienciaFisica?: BoolNullableFilter<"Participante2025"> | boolean | null
    deficienciaOutra?: BoolNullableFilter<"Participante2025"> | boolean | null
    deficienciaOutraDescricao?: StringNullableFilter<"Participante2025"> | string | null
    otherInstitution?: StringNullableFilter<"Participante2025"> | string | null
    instituicao?: XOR<InstituicaoEspiritaNullableScalarRelationFilter, InstituicaoEspiritaWhereInput> | null
    user?: XOR<UsersNullableScalarRelationFilter, UsersWhereInput> | null
  }, "id">

  export type Participante2025OrderByWithAggregationInput = {
    id?: SortOrder
    nomeCompleto?: SortOrder
    nomeCracha?: SortOrderInput | SortOrder
    cpf?: SortOrderInput | SortOrder
    nomeSocial?: SortOrderInput | SortOrder
    dataNascimento?: SortOrder
    sexo?: SortOrder
    email?: SortOrder
    telefone?: SortOrder
    nomeCompletoResponsavel?: SortOrderInput | SortOrder
    documentoResponsavel?: SortOrderInput | SortOrder
    telefoneResponsavel?: SortOrderInput | SortOrder
    linkPagamento?: SortOrderInput | SortOrder
    idade?: SortOrderInput | SortOrder
    valor?: SortOrderInput | SortOrder
    statusPagamento?: SortOrderInput | SortOrder
    tipoParticipacao?: SortOrder
    comissao?: SortOrderInput | SortOrder
    tamanhoCamisa?: SortOrderInput | SortOrder
    cep?: SortOrder
    estado?: SortOrderInput | SortOrder
    cidade?: SortOrderInput | SortOrder
    bairro?: SortOrderInput | SortOrder
    logradouro?: SortOrderInput | SortOrder
    numero?: SortOrderInput | SortOrder
    complemento?: SortOrderInput | SortOrder
    outroGenero?: SortOrderInput | SortOrder
    medicacao?: SortOrderInput | SortOrder
    alergia?: SortOrderInput | SortOrder
    outrasInformacoes?: SortOrderInput | SortOrder
    userId?: SortOrderInput | SortOrder
    createdAt?: SortOrder
    updatedAt?: SortOrder
    IE?: SortOrder
    instituicaoId?: SortOrderInput | SortOrder
    vegetariano?: SortOrder
    camisa?: SortOrderInput | SortOrder
    primeiraComejaca?: SortOrderInput | SortOrder
    deficienciaAuditiva?: SortOrderInput | SortOrder
    deficienciaAutismo?: SortOrderInput | SortOrder
    deficienciaIntelectual?: SortOrderInput | SortOrder
    deficienciaParalisiaCerebral?: SortOrderInput | SortOrder
    deficienciaVisual?: SortOrderInput | SortOrder
    deficienciaFisica?: SortOrderInput | SortOrder
    deficienciaOutra?: SortOrderInput | SortOrder
    deficienciaOutraDescricao?: SortOrderInput | SortOrder
    otherInstitution?: SortOrderInput | SortOrder
    _count?: Participante2025CountOrderByAggregateInput
    _avg?: Participante2025AvgOrderByAggregateInput
    _max?: Participante2025MaxOrderByAggregateInput
    _min?: Participante2025MinOrderByAggregateInput
    _sum?: Participante2025SumOrderByAggregateInput
  }

  export type Participante2025ScalarWhereWithAggregatesInput = {
    AND?: Participante2025ScalarWhereWithAggregatesInput | Participante2025ScalarWhereWithAggregatesInput[]
    OR?: Participante2025ScalarWhereWithAggregatesInput[]
    NOT?: Participante2025ScalarWhereWithAggregatesInput | Participante2025ScalarWhereWithAggregatesInput[]
    id?: StringWithAggregatesFilter<"Participante2025"> | string
    nomeCompleto?: StringWithAggregatesFilter<"Participante2025"> | string
    nomeCracha?: StringNullableWithAggregatesFilter<"Participante2025"> | string | null
    cpf?: StringNullableWithAggregatesFilter<"Participante2025"> | string | null
    nomeSocial?: StringNullableWithAggregatesFilter<"Participante2025"> | string | null
    dataNascimento?: DateTimeWithAggregatesFilter<"Participante2025"> | Date | string
    sexo?: StringWithAggregatesFilter<"Participante2025"> | string
    email?: StringWithAggregatesFilter<"Participante2025"> | string
    telefone?: StringWithAggregatesFilter<"Participante2025"> | string
    nomeCompletoResponsavel?: StringNullableWithAggregatesFilter<"Participante2025"> | string | null
    documentoResponsavel?: StringNullableWithAggregatesFilter<"Participante2025"> | string | null
    telefoneResponsavel?: StringNullableWithAggregatesFilter<"Participante2025"> | string | null
    linkPagamento?: StringNullableWithAggregatesFilter<"Participante2025"> | string | null
    idade?: IntNullableWithAggregatesFilter<"Participante2025"> | number | null
    valor?: FloatNullableWithAggregatesFilter<"Participante2025"> | number | null
    statusPagamento?: StringNullableWithAggregatesFilter<"Participante2025"> | string | null
    tipoParticipacao?: EnumTipoParticipacaoWithAggregatesFilter<"Participante2025"> | $Enums.TipoParticipacao
    comissao?: StringNullableWithAggregatesFilter<"Participante2025"> | string | null
    tamanhoCamisa?: StringNullableWithAggregatesFilter<"Participante2025"> | string | null
    cep?: StringWithAggregatesFilter<"Participante2025"> | string
    estado?: StringNullableWithAggregatesFilter<"Participante2025"> | string | null
    cidade?: StringNullableWithAggregatesFilter<"Participante2025"> | string | null
    bairro?: StringNullableWithAggregatesFilter<"Participante2025"> | string | null
    logradouro?: StringNullableWithAggregatesFilter<"Participante2025"> | string | null
    numero?: StringNullableWithAggregatesFilter<"Participante2025"> | string | null
    complemento?: StringNullableWithAggregatesFilter<"Participante2025"> | string | null
    outroGenero?: StringNullableWithAggregatesFilter<"Participante2025"> | string | null
    medicacao?: StringNullableWithAggregatesFilter<"Participante2025"> | string | null
    alergia?: StringNullableWithAggregatesFilter<"Participante2025"> | string | null
    outrasInformacoes?: StringNullableWithAggregatesFilter<"Participante2025"> | string | null
    userId?: IntNullableWithAggregatesFilter<"Participante2025"> | number | null
    createdAt?: DateTimeWithAggregatesFilter<"Participante2025"> | Date | string
    updatedAt?: DateTimeWithAggregatesFilter<"Participante2025"> | Date | string
    IE?: StringWithAggregatesFilter<"Participante2025"> | string
    instituicaoId?: IntNullableWithAggregatesFilter<"Participante2025"> | number | null
    vegetariano?: StringWithAggregatesFilter<"Participante2025"> | string
    camisa?: BoolNullableWithAggregatesFilter<"Participante2025"> | boolean | null
    primeiraComejaca?: BoolNullableWithAggregatesFilter<"Participante2025"> | boolean | null
    deficienciaAuditiva?: BoolNullableWithAggregatesFilter<"Participante2025"> | boolean | null
    deficienciaAutismo?: BoolNullableWithAggregatesFilter<"Participante2025"> | boolean | null
    deficienciaIntelectual?: BoolNullableWithAggregatesFilter<"Participante2025"> | boolean | null
    deficienciaParalisiaCerebral?: BoolNullableWithAggregatesFilter<"Participante2025"> | boolean | null
    deficienciaVisual?: BoolNullableWithAggregatesFilter<"Participante2025"> | boolean | null
    deficienciaFisica?: BoolNullableWithAggregatesFilter<"Participante2025"> | boolean | null
    deficienciaOutra?: BoolNullableWithAggregatesFilter<"Participante2025"> | boolean | null
    deficienciaOutraDescricao?: StringNullableWithAggregatesFilter<"Participante2025"> | string | null
    otherInstitution?: StringNullableWithAggregatesFilter<"Participante2025"> | string | null
  }

  export type PasswordResetTokenWhereInput = {
    AND?: PasswordResetTokenWhereInput | PasswordResetTokenWhereInput[]
    OR?: PasswordResetTokenWhereInput[]
    NOT?: PasswordResetTokenWhereInput | PasswordResetTokenWhereInput[]
    id?: IntFilter<"PasswordResetToken"> | number
    token?: StringFilter<"PasswordResetToken"> | string
    userId?: IntFilter<"PasswordResetToken"> | number
    expiresAt?: DateTimeFilter<"PasswordResetToken"> | Date | string
    createdAt?: DateTimeFilter<"PasswordResetToken"> | Date | string
    user?: XOR<UsersScalarRelationFilter, UsersWhereInput>
  }

  export type PasswordResetTokenOrderByWithRelationInput = {
    id?: SortOrder
    token?: SortOrder
    userId?: SortOrder
    expiresAt?: SortOrder
    createdAt?: SortOrder
    user?: UsersOrderByWithRelationInput
  }

  export type PasswordResetTokenWhereUniqueInput = Prisma.AtLeast<{
    id?: number
    token?: string
    AND?: PasswordResetTokenWhereInput | PasswordResetTokenWhereInput[]
    OR?: PasswordResetTokenWhereInput[]
    NOT?: PasswordResetTokenWhereInput | PasswordResetTokenWhereInput[]
    userId?: IntFilter<"PasswordResetToken"> | number
    expiresAt?: DateTimeFilter<"PasswordResetToken"> | Date | string
    createdAt?: DateTimeFilter<"PasswordResetToken"> | Date | string
    user?: XOR<UsersScalarRelationFilter, UsersWhereInput>
  }, "id" | "token">

  export type PasswordResetTokenOrderByWithAggregationInput = {
    id?: SortOrder
    token?: SortOrder
    userId?: SortOrder
    expiresAt?: SortOrder
    createdAt?: SortOrder
    _count?: PasswordResetTokenCountOrderByAggregateInput
    _avg?: PasswordResetTokenAvgOrderByAggregateInput
    _max?: PasswordResetTokenMaxOrderByAggregateInput
    _min?: PasswordResetTokenMinOrderByAggregateInput
    _sum?: PasswordResetTokenSumOrderByAggregateInput
  }

  export type PasswordResetTokenScalarWhereWithAggregatesInput = {
    AND?: PasswordResetTokenScalarWhereWithAggregatesInput | PasswordResetTokenScalarWhereWithAggregatesInput[]
    OR?: PasswordResetTokenScalarWhereWithAggregatesInput[]
    NOT?: PasswordResetTokenScalarWhereWithAggregatesInput | PasswordResetTokenScalarWhereWithAggregatesInput[]
    id?: IntWithAggregatesFilter<"PasswordResetToken"> | number
    token?: StringWithAggregatesFilter<"PasswordResetToken"> | string
    userId?: IntWithAggregatesFilter<"PasswordResetToken"> | number
    expiresAt?: DateTimeWithAggregatesFilter<"PasswordResetToken"> | Date | string
    createdAt?: DateTimeWithAggregatesFilter<"PasswordResetToken"> | Date | string
  }

  export type UsersCreateInput = {
    name: string
    email: string
    password: string
    isVerified?: boolean
    createdAt?: Date | string
    updatedAt?: Date | string
    verificationCode?: string | null
    verificationCodeExpiration?: Date | string | null
    lastVerificationRequest?: Date | string
    role?: $Enums.Role
    comunicacaocomejaca?: string | null
    comunicacaomovimento?: string | null
    telefone?: string | null
    resetTokenVersion?: number
    instituicoesAtualizadas?: InstituicaoEspiritaCreateNestedManyWithoutAtualizadoPorInput
    instituicoesCriadas?: InstituicaoEspiritaCreateNestedManyWithoutCriadoPorInput
    Participante2025?: Participante2025CreateNestedManyWithoutUserInput
    instituicoes?: InstituicaoEspiritaCreateNestedManyWithoutUsersInput
    passwordResetTokens?: PasswordResetTokenCreateNestedManyWithoutUserInput
  }

  export type UsersUncheckedCreateInput = {
    id?: number
    name: string
    email: string
    password: string
    isVerified?: boolean
    createdAt?: Date | string
    updatedAt?: Date | string
    verificationCode?: string | null
    verificationCodeExpiration?: Date | string | null
    lastVerificationRequest?: Date | string
    role?: $Enums.Role
    comunicacaocomejaca?: string | null
    comunicacaomovimento?: string | null
    telefone?: string | null
    resetTokenVersion?: number
    instituicoesAtualizadas?: InstituicaoEspiritaUncheckedCreateNestedManyWithoutAtualizadoPorInput
    instituicoesCriadas?: InstituicaoEspiritaUncheckedCreateNestedManyWithoutCriadoPorInput
    Participante2025?: Participante2025UncheckedCreateNestedManyWithoutUserInput
    instituicoes?: InstituicaoEspiritaUncheckedCreateNestedManyWithoutUsersInput
    passwordResetTokens?: PasswordResetTokenUncheckedCreateNestedManyWithoutUserInput
  }

  export type UsersUpdateInput = {
    name?: StringFieldUpdateOperationsInput | string
    email?: StringFieldUpdateOperationsInput | string
    password?: StringFieldUpdateOperationsInput | string
    isVerified?: BoolFieldUpdateOperationsInput | boolean
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    verificationCode?: NullableStringFieldUpdateOperationsInput | string | null
    verificationCodeExpiration?: NullableDateTimeFieldUpdateOperationsInput | Date | string | null
    lastVerificationRequest?: DateTimeFieldUpdateOperationsInput | Date | string
    role?: EnumRoleFieldUpdateOperationsInput | $Enums.Role
    comunicacaocomejaca?: NullableStringFieldUpdateOperationsInput | string | null
    comunicacaomovimento?: NullableStringFieldUpdateOperationsInput | string | null
    telefone?: NullableStringFieldUpdateOperationsInput | string | null
    resetTokenVersion?: IntFieldUpdateOperationsInput | number
    instituicoesAtualizadas?: InstituicaoEspiritaUpdateManyWithoutAtualizadoPorNestedInput
    instituicoesCriadas?: InstituicaoEspiritaUpdateManyWithoutCriadoPorNestedInput
    Participante2025?: Participante2025UpdateManyWithoutUserNestedInput
    instituicoes?: InstituicaoEspiritaUpdateManyWithoutUsersNestedInput
    passwordResetTokens?: PasswordResetTokenUpdateManyWithoutUserNestedInput
  }

  export type UsersUncheckedUpdateInput = {
    id?: IntFieldUpdateOperationsInput | number
    name?: StringFieldUpdateOperationsInput | string
    email?: StringFieldUpdateOperationsInput | string
    password?: StringFieldUpdateOperationsInput | string
    isVerified?: BoolFieldUpdateOperationsInput | boolean
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    verificationCode?: NullableStringFieldUpdateOperationsInput | string | null
    verificationCodeExpiration?: NullableDateTimeFieldUpdateOperationsInput | Date | string | null
    lastVerificationRequest?: DateTimeFieldUpdateOperationsInput | Date | string
    role?: EnumRoleFieldUpdateOperationsInput | $Enums.Role
    comunicacaocomejaca?: NullableStringFieldUpdateOperationsInput | string | null
    comunicacaomovimento?: NullableStringFieldUpdateOperationsInput | string | null
    telefone?: NullableStringFieldUpdateOperationsInput | string | null
    resetTokenVersion?: IntFieldUpdateOperationsInput | number
    instituicoesAtualizadas?: InstituicaoEspiritaUncheckedUpdateManyWithoutAtualizadoPorNestedInput
    instituicoesCriadas?: InstituicaoEspiritaUncheckedUpdateManyWithoutCriadoPorNestedInput
    Participante2025?: Participante2025UncheckedUpdateManyWithoutUserNestedInput
    instituicoes?: InstituicaoEspiritaUncheckedUpdateManyWithoutUsersNestedInput
    passwordResetTokens?: PasswordResetTokenUncheckedUpdateManyWithoutUserNestedInput
  }

  export type UsersCreateManyInput = {
    id?: number
    name: string
    email: string
    password: string
    isVerified?: boolean
    createdAt?: Date | string
    updatedAt?: Date | string
    verificationCode?: string | null
    verificationCodeExpiration?: Date | string | null
    lastVerificationRequest?: Date | string
    role?: $Enums.Role
    comunicacaocomejaca?: string | null
    comunicacaomovimento?: string | null
    telefone?: string | null
    resetTokenVersion?: number
  }

  export type UsersUpdateManyMutationInput = {
    name?: StringFieldUpdateOperationsInput | string
    email?: StringFieldUpdateOperationsInput | string
    password?: StringFieldUpdateOperationsInput | string
    isVerified?: BoolFieldUpdateOperationsInput | boolean
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    verificationCode?: NullableStringFieldUpdateOperationsInput | string | null
    verificationCodeExpiration?: NullableDateTimeFieldUpdateOperationsInput | Date | string | null
    lastVerificationRequest?: DateTimeFieldUpdateOperationsInput | Date | string
    role?: EnumRoleFieldUpdateOperationsInput | $Enums.Role
    comunicacaocomejaca?: NullableStringFieldUpdateOperationsInput | string | null
    comunicacaomovimento?: NullableStringFieldUpdateOperationsInput | string | null
    telefone?: NullableStringFieldUpdateOperationsInput | string | null
    resetTokenVersion?: IntFieldUpdateOperationsInput | number
  }

  export type UsersUncheckedUpdateManyInput = {
    id?: IntFieldUpdateOperationsInput | number
    name?: StringFieldUpdateOperationsInput | string
    email?: StringFieldUpdateOperationsInput | string
    password?: StringFieldUpdateOperationsInput | string
    isVerified?: BoolFieldUpdateOperationsInput | boolean
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    verificationCode?: NullableStringFieldUpdateOperationsInput | string | null
    verificationCodeExpiration?: NullableDateTimeFieldUpdateOperationsInput | Date | string | null
    lastVerificationRequest?: DateTimeFieldUpdateOperationsInput | Date | string
    role?: EnumRoleFieldUpdateOperationsInput | $Enums.Role
    comunicacaocomejaca?: NullableStringFieldUpdateOperationsInput | string | null
    comunicacaomovimento?: NullableStringFieldUpdateOperationsInput | string | null
    telefone?: NullableStringFieldUpdateOperationsInput | string | null
    resetTokenVersion?: IntFieldUpdateOperationsInput | number
  }

  export type InstituicaoEspiritaCreateInput = {
    nome: string
    nome_CNPJ?: string | null
    estado?: string | null
    cidade?: string | null
    bairro?: string | null
    logradouro?: string | null
    numero?: string | null
    complemento?: string | null
    telefone?: string | null
    email?: string | null
    createdAt?: Date | string
    updatedAt?: Date | string
    sigla: string
    CEU?: string | null
    dia?: string | null
    horario?: string | null
    CNPJ: string
    atualizadoPor?: UsersCreateNestedOneWithoutInstituicoesAtualizadasInput
    criadoPor?: UsersCreateNestedOneWithoutInstituicoesCriadasInput
    Participante2025?: Participante2025CreateNestedManyWithoutInstituicaoInput
    Users?: UsersCreateNestedManyWithoutInstituicoesInput
  }

  export type InstituicaoEspiritaUncheckedCreateInput = {
    id?: number
    nome: string
    nome_CNPJ?: string | null
    estado?: string | null
    cidade?: string | null
    bairro?: string | null
    logradouro?: string | null
    numero?: string | null
    complemento?: string | null
    telefone?: string | null
    email?: string | null
    createdAt?: Date | string
    updatedAt?: Date | string
    criadoPorId?: number | null
    sigla: string
    CEU?: string | null
    dia?: string | null
    horario?: string | null
    atualizadoPorId?: number | null
    CNPJ: string
    Participante2025?: Participante2025UncheckedCreateNestedManyWithoutInstituicaoInput
    Users?: UsersUncheckedCreateNestedManyWithoutInstituicoesInput
  }

  export type InstituicaoEspiritaUpdateInput = {
    nome?: StringFieldUpdateOperationsInput | string
    nome_CNPJ?: NullableStringFieldUpdateOperationsInput | string | null
    estado?: NullableStringFieldUpdateOperationsInput | string | null
    cidade?: NullableStringFieldUpdateOperationsInput | string | null
    bairro?: NullableStringFieldUpdateOperationsInput | string | null
    logradouro?: NullableStringFieldUpdateOperationsInput | string | null
    numero?: NullableStringFieldUpdateOperationsInput | string | null
    complemento?: NullableStringFieldUpdateOperationsInput | string | null
    telefone?: NullableStringFieldUpdateOperationsInput | string | null
    email?: NullableStringFieldUpdateOperationsInput | string | null
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    sigla?: StringFieldUpdateOperationsInput | string
    CEU?: NullableStringFieldUpdateOperationsInput | string | null
    dia?: NullableStringFieldUpdateOperationsInput | string | null
    horario?: NullableStringFieldUpdateOperationsInput | string | null
    CNPJ?: StringFieldUpdateOperationsInput | string
    atualizadoPor?: UsersUpdateOneWithoutInstituicoesAtualizadasNestedInput
    criadoPor?: UsersUpdateOneWithoutInstituicoesCriadasNestedInput
    Participante2025?: Participante2025UpdateManyWithoutInstituicaoNestedInput
    Users?: UsersUpdateManyWithoutInstituicoesNestedInput
  }

  export type InstituicaoEspiritaUncheckedUpdateInput = {
    id?: IntFieldUpdateOperationsInput | number
    nome?: StringFieldUpdateOperationsInput | string
    nome_CNPJ?: NullableStringFieldUpdateOperationsInput | string | null
    estado?: NullableStringFieldUpdateOperationsInput | string | null
    cidade?: NullableStringFieldUpdateOperationsInput | string | null
    bairro?: NullableStringFieldUpdateOperationsInput | string | null
    logradouro?: NullableStringFieldUpdateOperationsInput | string | null
    numero?: NullableStringFieldUpdateOperationsInput | string | null
    complemento?: NullableStringFieldUpdateOperationsInput | string | null
    telefone?: NullableStringFieldUpdateOperationsInput | string | null
    email?: NullableStringFieldUpdateOperationsInput | string | null
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    criadoPorId?: NullableIntFieldUpdateOperationsInput | number | null
    sigla?: StringFieldUpdateOperationsInput | string
    CEU?: NullableStringFieldUpdateOperationsInput | string | null
    dia?: NullableStringFieldUpdateOperationsInput | string | null
    horario?: NullableStringFieldUpdateOperationsInput | string | null
    atualizadoPorId?: NullableIntFieldUpdateOperationsInput | number | null
    CNPJ?: StringFieldUpdateOperationsInput | string
    Participante2025?: Participante2025UncheckedUpdateManyWithoutInstituicaoNestedInput
    Users?: UsersUncheckedUpdateManyWithoutInstituicoesNestedInput
  }

  export type InstituicaoEspiritaCreateManyInput = {
    id?: number
    nome: string
    nome_CNPJ?: string | null
    estado?: string | null
    cidade?: string | null
    bairro?: string | null
    logradouro?: string | null
    numero?: string | null
    complemento?: string | null
    telefone?: string | null
    email?: string | null
    createdAt?: Date | string
    updatedAt?: Date | string
    criadoPorId?: number | null
    sigla: string
    CEU?: string | null
    dia?: string | null
    horario?: string | null
    atualizadoPorId?: number | null
    CNPJ: string
  }

  export type InstituicaoEspiritaUpdateManyMutationInput = {
    nome?: StringFieldUpdateOperationsInput | string
    nome_CNPJ?: NullableStringFieldUpdateOperationsInput | string | null
    estado?: NullableStringFieldUpdateOperationsInput | string | null
    cidade?: NullableStringFieldUpdateOperationsInput | string | null
    bairro?: NullableStringFieldUpdateOperationsInput | string | null
    logradouro?: NullableStringFieldUpdateOperationsInput | string | null
    numero?: NullableStringFieldUpdateOperationsInput | string | null
    complemento?: NullableStringFieldUpdateOperationsInput | string | null
    telefone?: NullableStringFieldUpdateOperationsInput | string | null
    email?: NullableStringFieldUpdateOperationsInput | string | null
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    sigla?: StringFieldUpdateOperationsInput | string
    CEU?: NullableStringFieldUpdateOperationsInput | string | null
    dia?: NullableStringFieldUpdateOperationsInput | string | null
    horario?: NullableStringFieldUpdateOperationsInput | string | null
    CNPJ?: StringFieldUpdateOperationsInput | string
  }

  export type InstituicaoEspiritaUncheckedUpdateManyInput = {
    id?: IntFieldUpdateOperationsInput | number
    nome?: StringFieldUpdateOperationsInput | string
    nome_CNPJ?: NullableStringFieldUpdateOperationsInput | string | null
    estado?: NullableStringFieldUpdateOperationsInput | string | null
    cidade?: NullableStringFieldUpdateOperationsInput | string | null
    bairro?: NullableStringFieldUpdateOperationsInput | string | null
    logradouro?: NullableStringFieldUpdateOperationsInput | string | null
    numero?: NullableStringFieldUpdateOperationsInput | string | null
    complemento?: NullableStringFieldUpdateOperationsInput | string | null
    telefone?: NullableStringFieldUpdateOperationsInput | string | null
    email?: NullableStringFieldUpdateOperationsInput | string | null
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    criadoPorId?: NullableIntFieldUpdateOperationsInput | number | null
    sigla?: StringFieldUpdateOperationsInput | string
    CEU?: NullableStringFieldUpdateOperationsInput | string | null
    dia?: NullableStringFieldUpdateOperationsInput | string | null
    horario?: NullableStringFieldUpdateOperationsInput | string | null
    atualizadoPorId?: NullableIntFieldUpdateOperationsInput | number | null
    CNPJ?: StringFieldUpdateOperationsInput | string
  }

  export type Participante2025CreateInput = {
    id?: string
    nomeCompleto: string
    nomeCracha?: string | null
    cpf?: string | null
    nomeSocial?: string | null
    dataNascimento: Date | string
    sexo: string
    email: string
    telefone: string
    nomeCompletoResponsavel?: string | null
    documentoResponsavel?: string | null
    telefoneResponsavel?: string | null
    linkPagamento?: string | null
    idade?: number | null
    valor?: number | null
    statusPagamento?: string | null
    tipoParticipacao: $Enums.TipoParticipacao
    comissao?: string | null
    tamanhoCamisa?: string | null
    cep: string
    estado?: string | null
    cidade?: string | null
    bairro?: string | null
    logradouro?: string | null
    numero?: string | null
    complemento?: string | null
    outroGenero?: string | null
    medicacao?: string | null
    alergia?: string | null
    outrasInformacoes?: string | null
    createdAt?: Date | string
    updatedAt?: Date | string
    IE: string
    vegetariano?: string
    camisa?: boolean | null
    primeiraComejaca?: boolean | null
    deficienciaAuditiva?: boolean | null
    deficienciaAutismo?: boolean | null
    deficienciaIntelectual?: boolean | null
    deficienciaParalisiaCerebral?: boolean | null
    deficienciaVisual?: boolean | null
    deficienciaFisica?: boolean | null
    deficienciaOutra?: boolean | null
    deficienciaOutraDescricao?: string | null
    otherInstitution?: string | null
    instituicao?: InstituicaoEspiritaCreateNestedOneWithoutParticipante2025Input
    user?: UsersCreateNestedOneWithoutParticipante2025Input
  }

  export type Participante2025UncheckedCreateInput = {
    id?: string
    nomeCompleto: string
    nomeCracha?: string | null
    cpf?: string | null
    nomeSocial?: string | null
    dataNascimento: Date | string
    sexo: string
    email: string
    telefone: string
    nomeCompletoResponsavel?: string | null
    documentoResponsavel?: string | null
    telefoneResponsavel?: string | null
    linkPagamento?: string | null
    idade?: number | null
    valor?: number | null
    statusPagamento?: string | null
    tipoParticipacao: $Enums.TipoParticipacao
    comissao?: string | null
    tamanhoCamisa?: string | null
    cep: string
    estado?: string | null
    cidade?: string | null
    bairro?: string | null
    logradouro?: string | null
    numero?: string | null
    complemento?: string | null
    outroGenero?: string | null
    medicacao?: string | null
    alergia?: string | null
    outrasInformacoes?: string | null
    userId?: number | null
    createdAt?: Date | string
    updatedAt?: Date | string
    IE: string
    instituicaoId?: number | null
    vegetariano?: string
    camisa?: boolean | null
    primeiraComejaca?: boolean | null
    deficienciaAuditiva?: boolean | null
    deficienciaAutismo?: boolean | null
    deficienciaIntelectual?: boolean | null
    deficienciaParalisiaCerebral?: boolean | null
    deficienciaVisual?: boolean | null
    deficienciaFisica?: boolean | null
    deficienciaOutra?: boolean | null
    deficienciaOutraDescricao?: string | null
    otherInstitution?: string | null
  }

  export type Participante2025UpdateInput = {
    id?: StringFieldUpdateOperationsInput | string
    nomeCompleto?: StringFieldUpdateOperationsInput | string
    nomeCracha?: NullableStringFieldUpdateOperationsInput | string | null
    cpf?: NullableStringFieldUpdateOperationsInput | string | null
    nomeSocial?: NullableStringFieldUpdateOperationsInput | string | null
    dataNascimento?: DateTimeFieldUpdateOperationsInput | Date | string
    sexo?: StringFieldUpdateOperationsInput | string
    email?: StringFieldUpdateOperationsInput | string
    telefone?: StringFieldUpdateOperationsInput | string
    nomeCompletoResponsavel?: NullableStringFieldUpdateOperationsInput | string | null
    documentoResponsavel?: NullableStringFieldUpdateOperationsInput | string | null
    telefoneResponsavel?: NullableStringFieldUpdateOperationsInput | string | null
    linkPagamento?: NullableStringFieldUpdateOperationsInput | string | null
    idade?: NullableIntFieldUpdateOperationsInput | number | null
    valor?: NullableFloatFieldUpdateOperationsInput | number | null
    statusPagamento?: NullableStringFieldUpdateOperationsInput | string | null
    tipoParticipacao?: EnumTipoParticipacaoFieldUpdateOperationsInput | $Enums.TipoParticipacao
    comissao?: NullableStringFieldUpdateOperationsInput | string | null
    tamanhoCamisa?: NullableStringFieldUpdateOperationsInput | string | null
    cep?: StringFieldUpdateOperationsInput | string
    estado?: NullableStringFieldUpdateOperationsInput | string | null
    cidade?: NullableStringFieldUpdateOperationsInput | string | null
    bairro?: NullableStringFieldUpdateOperationsInput | string | null
    logradouro?: NullableStringFieldUpdateOperationsInput | string | null
    numero?: NullableStringFieldUpdateOperationsInput | string | null
    complemento?: NullableStringFieldUpdateOperationsInput | string | null
    outroGenero?: NullableStringFieldUpdateOperationsInput | string | null
    medicacao?: NullableStringFieldUpdateOperationsInput | string | null
    alergia?: NullableStringFieldUpdateOperationsInput | string | null
    outrasInformacoes?: NullableStringFieldUpdateOperationsInput | string | null
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    IE?: StringFieldUpdateOperationsInput | string
    vegetariano?: StringFieldUpdateOperationsInput | string
    camisa?: NullableBoolFieldUpdateOperationsInput | boolean | null
    primeiraComejaca?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaAuditiva?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaAutismo?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaIntelectual?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaParalisiaCerebral?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaVisual?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaFisica?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaOutra?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaOutraDescricao?: NullableStringFieldUpdateOperationsInput | string | null
    otherInstitution?: NullableStringFieldUpdateOperationsInput | string | null
    instituicao?: InstituicaoEspiritaUpdateOneWithoutParticipante2025NestedInput
    user?: UsersUpdateOneWithoutParticipante2025NestedInput
  }

  export type Participante2025UncheckedUpdateInput = {
    id?: StringFieldUpdateOperationsInput | string
    nomeCompleto?: StringFieldUpdateOperationsInput | string
    nomeCracha?: NullableStringFieldUpdateOperationsInput | string | null
    cpf?: NullableStringFieldUpdateOperationsInput | string | null
    nomeSocial?: NullableStringFieldUpdateOperationsInput | string | null
    dataNascimento?: DateTimeFieldUpdateOperationsInput | Date | string
    sexo?: StringFieldUpdateOperationsInput | string
    email?: StringFieldUpdateOperationsInput | string
    telefone?: StringFieldUpdateOperationsInput | string
    nomeCompletoResponsavel?: NullableStringFieldUpdateOperationsInput | string | null
    documentoResponsavel?: NullableStringFieldUpdateOperationsInput | string | null
    telefoneResponsavel?: NullableStringFieldUpdateOperationsInput | string | null
    linkPagamento?: NullableStringFieldUpdateOperationsInput | string | null
    idade?: NullableIntFieldUpdateOperationsInput | number | null
    valor?: NullableFloatFieldUpdateOperationsInput | number | null
    statusPagamento?: NullableStringFieldUpdateOperationsInput | string | null
    tipoParticipacao?: EnumTipoParticipacaoFieldUpdateOperationsInput | $Enums.TipoParticipacao
    comissao?: NullableStringFieldUpdateOperationsInput | string | null
    tamanhoCamisa?: NullableStringFieldUpdateOperationsInput | string | null
    cep?: StringFieldUpdateOperationsInput | string
    estado?: NullableStringFieldUpdateOperationsInput | string | null
    cidade?: NullableStringFieldUpdateOperationsInput | string | null
    bairro?: NullableStringFieldUpdateOperationsInput | string | null
    logradouro?: NullableStringFieldUpdateOperationsInput | string | null
    numero?: NullableStringFieldUpdateOperationsInput | string | null
    complemento?: NullableStringFieldUpdateOperationsInput | string | null
    outroGenero?: NullableStringFieldUpdateOperationsInput | string | null
    medicacao?: NullableStringFieldUpdateOperationsInput | string | null
    alergia?: NullableStringFieldUpdateOperationsInput | string | null
    outrasInformacoes?: NullableStringFieldUpdateOperationsInput | string | null
    userId?: NullableIntFieldUpdateOperationsInput | number | null
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    IE?: StringFieldUpdateOperationsInput | string
    instituicaoId?: NullableIntFieldUpdateOperationsInput | number | null
    vegetariano?: StringFieldUpdateOperationsInput | string
    camisa?: NullableBoolFieldUpdateOperationsInput | boolean | null
    primeiraComejaca?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaAuditiva?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaAutismo?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaIntelectual?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaParalisiaCerebral?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaVisual?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaFisica?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaOutra?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaOutraDescricao?: NullableStringFieldUpdateOperationsInput | string | null
    otherInstitution?: NullableStringFieldUpdateOperationsInput | string | null
  }

  export type Participante2025CreateManyInput = {
    id?: string
    nomeCompleto: string
    nomeCracha?: string | null
    cpf?: string | null
    nomeSocial?: string | null
    dataNascimento: Date | string
    sexo: string
    email: string
    telefone: string
    nomeCompletoResponsavel?: string | null
    documentoResponsavel?: string | null
    telefoneResponsavel?: string | null
    linkPagamento?: string | null
    idade?: number | null
    valor?: number | null
    statusPagamento?: string | null
    tipoParticipacao: $Enums.TipoParticipacao
    comissao?: string | null
    tamanhoCamisa?: string | null
    cep: string
    estado?: string | null
    cidade?: string | null
    bairro?: string | null
    logradouro?: string | null
    numero?: string | null
    complemento?: string | null
    outroGenero?: string | null
    medicacao?: string | null
    alergia?: string | null
    outrasInformacoes?: string | null
    userId?: number | null
    createdAt?: Date | string
    updatedAt?: Date | string
    IE: string
    instituicaoId?: number | null
    vegetariano?: string
    camisa?: boolean | null
    primeiraComejaca?: boolean | null
    deficienciaAuditiva?: boolean | null
    deficienciaAutismo?: boolean | null
    deficienciaIntelectual?: boolean | null
    deficienciaParalisiaCerebral?: boolean | null
    deficienciaVisual?: boolean | null
    deficienciaFisica?: boolean | null
    deficienciaOutra?: boolean | null
    deficienciaOutraDescricao?: string | null
    otherInstitution?: string | null
  }

  export type Participante2025UpdateManyMutationInput = {
    id?: StringFieldUpdateOperationsInput | string
    nomeCompleto?: StringFieldUpdateOperationsInput | string
    nomeCracha?: NullableStringFieldUpdateOperationsInput | string | null
    cpf?: NullableStringFieldUpdateOperationsInput | string | null
    nomeSocial?: NullableStringFieldUpdateOperationsInput | string | null
    dataNascimento?: DateTimeFieldUpdateOperationsInput | Date | string
    sexo?: StringFieldUpdateOperationsInput | string
    email?: StringFieldUpdateOperationsInput | string
    telefone?: StringFieldUpdateOperationsInput | string
    nomeCompletoResponsavel?: NullableStringFieldUpdateOperationsInput | string | null
    documentoResponsavel?: NullableStringFieldUpdateOperationsInput | string | null
    telefoneResponsavel?: NullableStringFieldUpdateOperationsInput | string | null
    linkPagamento?: NullableStringFieldUpdateOperationsInput | string | null
    idade?: NullableIntFieldUpdateOperationsInput | number | null
    valor?: NullableFloatFieldUpdateOperationsInput | number | null
    statusPagamento?: NullableStringFieldUpdateOperationsInput | string | null
    tipoParticipacao?: EnumTipoParticipacaoFieldUpdateOperationsInput | $Enums.TipoParticipacao
    comissao?: NullableStringFieldUpdateOperationsInput | string | null
    tamanhoCamisa?: NullableStringFieldUpdateOperationsInput | string | null
    cep?: StringFieldUpdateOperationsInput | string
    estado?: NullableStringFieldUpdateOperationsInput | string | null
    cidade?: NullableStringFieldUpdateOperationsInput | string | null
    bairro?: NullableStringFieldUpdateOperationsInput | string | null
    logradouro?: NullableStringFieldUpdateOperationsInput | string | null
    numero?: NullableStringFieldUpdateOperationsInput | string | null
    complemento?: NullableStringFieldUpdateOperationsInput | string | null
    outroGenero?: NullableStringFieldUpdateOperationsInput | string | null
    medicacao?: NullableStringFieldUpdateOperationsInput | string | null
    alergia?: NullableStringFieldUpdateOperationsInput | string | null
    outrasInformacoes?: NullableStringFieldUpdateOperationsInput | string | null
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    IE?: StringFieldUpdateOperationsInput | string
    vegetariano?: StringFieldUpdateOperationsInput | string
    camisa?: NullableBoolFieldUpdateOperationsInput | boolean | null
    primeiraComejaca?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaAuditiva?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaAutismo?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaIntelectual?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaParalisiaCerebral?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaVisual?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaFisica?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaOutra?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaOutraDescricao?: NullableStringFieldUpdateOperationsInput | string | null
    otherInstitution?: NullableStringFieldUpdateOperationsInput | string | null
  }

  export type Participante2025UncheckedUpdateManyInput = {
    id?: StringFieldUpdateOperationsInput | string
    nomeCompleto?: StringFieldUpdateOperationsInput | string
    nomeCracha?: NullableStringFieldUpdateOperationsInput | string | null
    cpf?: NullableStringFieldUpdateOperationsInput | string | null
    nomeSocial?: NullableStringFieldUpdateOperationsInput | string | null
    dataNascimento?: DateTimeFieldUpdateOperationsInput | Date | string
    sexo?: StringFieldUpdateOperationsInput | string
    email?: StringFieldUpdateOperationsInput | string
    telefone?: StringFieldUpdateOperationsInput | string
    nomeCompletoResponsavel?: NullableStringFieldUpdateOperationsInput | string | null
    documentoResponsavel?: NullableStringFieldUpdateOperationsInput | string | null
    telefoneResponsavel?: NullableStringFieldUpdateOperationsInput | string | null
    linkPagamento?: NullableStringFieldUpdateOperationsInput | string | null
    idade?: NullableIntFieldUpdateOperationsInput | number | null
    valor?: NullableFloatFieldUpdateOperationsInput | number | null
    statusPagamento?: NullableStringFieldUpdateOperationsInput | string | null
    tipoParticipacao?: EnumTipoParticipacaoFieldUpdateOperationsInput | $Enums.TipoParticipacao
    comissao?: NullableStringFieldUpdateOperationsInput | string | null
    tamanhoCamisa?: NullableStringFieldUpdateOperationsInput | string | null
    cep?: StringFieldUpdateOperationsInput | string
    estado?: NullableStringFieldUpdateOperationsInput | string | null
    cidade?: NullableStringFieldUpdateOperationsInput | string | null
    bairro?: NullableStringFieldUpdateOperationsInput | string | null
    logradouro?: NullableStringFieldUpdateOperationsInput | string | null
    numero?: NullableStringFieldUpdateOperationsInput | string | null
    complemento?: NullableStringFieldUpdateOperationsInput | string | null
    outroGenero?: NullableStringFieldUpdateOperationsInput | string | null
    medicacao?: NullableStringFieldUpdateOperationsInput | string | null
    alergia?: NullableStringFieldUpdateOperationsInput | string | null
    outrasInformacoes?: NullableStringFieldUpdateOperationsInput | string | null
    userId?: NullableIntFieldUpdateOperationsInput | number | null
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    IE?: StringFieldUpdateOperationsInput | string
    instituicaoId?: NullableIntFieldUpdateOperationsInput | number | null
    vegetariano?: StringFieldUpdateOperationsInput | string
    camisa?: NullableBoolFieldUpdateOperationsInput | boolean | null
    primeiraComejaca?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaAuditiva?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaAutismo?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaIntelectual?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaParalisiaCerebral?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaVisual?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaFisica?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaOutra?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaOutraDescricao?: NullableStringFieldUpdateOperationsInput | string | null
    otherInstitution?: NullableStringFieldUpdateOperationsInput | string | null
  }

  export type PasswordResetTokenCreateInput = {
    token: string
    expiresAt: Date | string
    createdAt?: Date | string
    user: UsersCreateNestedOneWithoutPasswordResetTokensInput
  }

  export type PasswordResetTokenUncheckedCreateInput = {
    id?: number
    token: string
    userId: number
    expiresAt: Date | string
    createdAt?: Date | string
  }

  export type PasswordResetTokenUpdateInput = {
    token?: StringFieldUpdateOperationsInput | string
    expiresAt?: DateTimeFieldUpdateOperationsInput | Date | string
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    user?: UsersUpdateOneRequiredWithoutPasswordResetTokensNestedInput
  }

  export type PasswordResetTokenUncheckedUpdateInput = {
    id?: IntFieldUpdateOperationsInput | number
    token?: StringFieldUpdateOperationsInput | string
    userId?: IntFieldUpdateOperationsInput | number
    expiresAt?: DateTimeFieldUpdateOperationsInput | Date | string
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
  }

  export type PasswordResetTokenCreateManyInput = {
    id?: number
    token: string
    userId: number
    expiresAt: Date | string
    createdAt?: Date | string
  }

  export type PasswordResetTokenUpdateManyMutationInput = {
    token?: StringFieldUpdateOperationsInput | string
    expiresAt?: DateTimeFieldUpdateOperationsInput | Date | string
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
  }

  export type PasswordResetTokenUncheckedUpdateManyInput = {
    id?: IntFieldUpdateOperationsInput | number
    token?: StringFieldUpdateOperationsInput | string
    userId?: IntFieldUpdateOperationsInput | number
    expiresAt?: DateTimeFieldUpdateOperationsInput | Date | string
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
  }

  export type IntFilter<$PrismaModel = never> = {
    equals?: number | IntFieldRefInput<$PrismaModel>
    in?: number[] | ListIntFieldRefInput<$PrismaModel>
    notIn?: number[] | ListIntFieldRefInput<$PrismaModel>
    lt?: number | IntFieldRefInput<$PrismaModel>
    lte?: number | IntFieldRefInput<$PrismaModel>
    gt?: number | IntFieldRefInput<$PrismaModel>
    gte?: number | IntFieldRefInput<$PrismaModel>
    not?: NestedIntFilter<$PrismaModel> | number
  }

  export type StringFilter<$PrismaModel = never> = {
    equals?: string | StringFieldRefInput<$PrismaModel>
    in?: string[] | ListStringFieldRefInput<$PrismaModel>
    notIn?: string[] | ListStringFieldRefInput<$PrismaModel>
    lt?: string | StringFieldRefInput<$PrismaModel>
    lte?: string | StringFieldRefInput<$PrismaModel>
    gt?: string | StringFieldRefInput<$PrismaModel>
    gte?: string | StringFieldRefInput<$PrismaModel>
    contains?: string | StringFieldRefInput<$PrismaModel>
    startsWith?: string | StringFieldRefInput<$PrismaModel>
    endsWith?: string | StringFieldRefInput<$PrismaModel>
    mode?: QueryMode
    not?: NestedStringFilter<$PrismaModel> | string
  }

  export type BoolFilter<$PrismaModel = never> = {
    equals?: boolean | BooleanFieldRefInput<$PrismaModel>
    not?: NestedBoolFilter<$PrismaModel> | boolean
  }

  export type DateTimeFilter<$PrismaModel = never> = {
    equals?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    in?: Date[] | string[] | ListDateTimeFieldRefInput<$PrismaModel>
    notIn?: Date[] | string[] | ListDateTimeFieldRefInput<$PrismaModel>
    lt?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    lte?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    gt?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    gte?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    not?: NestedDateTimeFilter<$PrismaModel> | Date | string
  }

  export type StringNullableFilter<$PrismaModel = never> = {
    equals?: string | StringFieldRefInput<$PrismaModel> | null
    in?: string[] | ListStringFieldRefInput<$PrismaModel> | null
    notIn?: string[] | ListStringFieldRefInput<$PrismaModel> | null
    lt?: string | StringFieldRefInput<$PrismaModel>
    lte?: string | StringFieldRefInput<$PrismaModel>
    gt?: string | StringFieldRefInput<$PrismaModel>
    gte?: string | StringFieldRefInput<$PrismaModel>
    contains?: string | StringFieldRefInput<$PrismaModel>
    startsWith?: string | StringFieldRefInput<$PrismaModel>
    endsWith?: string | StringFieldRefInput<$PrismaModel>
    mode?: QueryMode
    not?: NestedStringNullableFilter<$PrismaModel> | string | null
  }

  export type DateTimeNullableFilter<$PrismaModel = never> = {
    equals?: Date | string | DateTimeFieldRefInput<$PrismaModel> | null
    in?: Date[] | string[] | ListDateTimeFieldRefInput<$PrismaModel> | null
    notIn?: Date[] | string[] | ListDateTimeFieldRefInput<$PrismaModel> | null
    lt?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    lte?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    gt?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    gte?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    not?: NestedDateTimeNullableFilter<$PrismaModel> | Date | string | null
  }

  export type EnumRoleFilter<$PrismaModel = never> = {
    equals?: $Enums.Role | EnumRoleFieldRefInput<$PrismaModel>
    in?: $Enums.Role[] | ListEnumRoleFieldRefInput<$PrismaModel>
    notIn?: $Enums.Role[] | ListEnumRoleFieldRefInput<$PrismaModel>
    not?: NestedEnumRoleFilter<$PrismaModel> | $Enums.Role
  }

  export type InstituicaoEspiritaListRelationFilter = {
    every?: InstituicaoEspiritaWhereInput
    some?: InstituicaoEspiritaWhereInput
    none?: InstituicaoEspiritaWhereInput
  }

  export type Participante2025ListRelationFilter = {
    every?: Participante2025WhereInput
    some?: Participante2025WhereInput
    none?: Participante2025WhereInput
  }

  export type PasswordResetTokenListRelationFilter = {
    every?: PasswordResetTokenWhereInput
    some?: PasswordResetTokenWhereInput
    none?: PasswordResetTokenWhereInput
  }

  export type SortOrderInput = {
    sort: SortOrder
    nulls?: NullsOrder
  }

  export type InstituicaoEspiritaOrderByRelationAggregateInput = {
    _count?: SortOrder
  }

  export type Participante2025OrderByRelationAggregateInput = {
    _count?: SortOrder
  }

  export type PasswordResetTokenOrderByRelationAggregateInput = {
    _count?: SortOrder
  }

  export type UsersCountOrderByAggregateInput = {
    id?: SortOrder
    name?: SortOrder
    email?: SortOrder
    password?: SortOrder
    isVerified?: SortOrder
    createdAt?: SortOrder
    updatedAt?: SortOrder
    verificationCode?: SortOrder
    verificationCodeExpiration?: SortOrder
    lastVerificationRequest?: SortOrder
    role?: SortOrder
    comunicacaocomejaca?: SortOrder
    comunicacaomovimento?: SortOrder
    telefone?: SortOrder
    resetTokenVersion?: SortOrder
  }

  export type UsersAvgOrderByAggregateInput = {
    id?: SortOrder
    resetTokenVersion?: SortOrder
  }

  export type UsersMaxOrderByAggregateInput = {
    id?: SortOrder
    name?: SortOrder
    email?: SortOrder
    password?: SortOrder
    isVerified?: SortOrder
    createdAt?: SortOrder
    updatedAt?: SortOrder
    verificationCode?: SortOrder
    verificationCodeExpiration?: SortOrder
    lastVerificationRequest?: SortOrder
    role?: SortOrder
    comunicacaocomejaca?: SortOrder
    comunicacaomovimento?: SortOrder
    telefone?: SortOrder
    resetTokenVersion?: SortOrder
  }

  export type UsersMinOrderByAggregateInput = {
    id?: SortOrder
    name?: SortOrder
    email?: SortOrder
    password?: SortOrder
    isVerified?: SortOrder
    createdAt?: SortOrder
    updatedAt?: SortOrder
    verificationCode?: SortOrder
    verificationCodeExpiration?: SortOrder
    lastVerificationRequest?: SortOrder
    role?: SortOrder
    comunicacaocomejaca?: SortOrder
    comunicacaomovimento?: SortOrder
    telefone?: SortOrder
    resetTokenVersion?: SortOrder
  }

  export type UsersSumOrderByAggregateInput = {
    id?: SortOrder
    resetTokenVersion?: SortOrder
  }

  export type IntWithAggregatesFilter<$PrismaModel = never> = {
    equals?: number | IntFieldRefInput<$PrismaModel>
    in?: number[] | ListIntFieldRefInput<$PrismaModel>
    notIn?: number[] | ListIntFieldRefInput<$PrismaModel>
    lt?: number | IntFieldRefInput<$PrismaModel>
    lte?: number | IntFieldRefInput<$PrismaModel>
    gt?: number | IntFieldRefInput<$PrismaModel>
    gte?: number | IntFieldRefInput<$PrismaModel>
    not?: NestedIntWithAggregatesFilter<$PrismaModel> | number
    _count?: NestedIntFilter<$PrismaModel>
    _avg?: NestedFloatFilter<$PrismaModel>
    _sum?: NestedIntFilter<$PrismaModel>
    _min?: NestedIntFilter<$PrismaModel>
    _max?: NestedIntFilter<$PrismaModel>
  }

  export type StringWithAggregatesFilter<$PrismaModel = never> = {
    equals?: string | StringFieldRefInput<$PrismaModel>
    in?: string[] | ListStringFieldRefInput<$PrismaModel>
    notIn?: string[] | ListStringFieldRefInput<$PrismaModel>
    lt?: string | StringFieldRefInput<$PrismaModel>
    lte?: string | StringFieldRefInput<$PrismaModel>
    gt?: string | StringFieldRefInput<$PrismaModel>
    gte?: string | StringFieldRefInput<$PrismaModel>
    contains?: string | StringFieldRefInput<$PrismaModel>
    startsWith?: string | StringFieldRefInput<$PrismaModel>
    endsWith?: string | StringFieldRefInput<$PrismaModel>
    mode?: QueryMode
    not?: NestedStringWithAggregatesFilter<$PrismaModel> | string
    _count?: NestedIntFilter<$PrismaModel>
    _min?: NestedStringFilter<$PrismaModel>
    _max?: NestedStringFilter<$PrismaModel>
  }

  export type BoolWithAggregatesFilter<$PrismaModel = never> = {
    equals?: boolean | BooleanFieldRefInput<$PrismaModel>
    not?: NestedBoolWithAggregatesFilter<$PrismaModel> | boolean
    _count?: NestedIntFilter<$PrismaModel>
    _min?: NestedBoolFilter<$PrismaModel>
    _max?: NestedBoolFilter<$PrismaModel>
  }

  export type DateTimeWithAggregatesFilter<$PrismaModel = never> = {
    equals?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    in?: Date[] | string[] | ListDateTimeFieldRefInput<$PrismaModel>
    notIn?: Date[] | string[] | ListDateTimeFieldRefInput<$PrismaModel>
    lt?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    lte?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    gt?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    gte?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    not?: NestedDateTimeWithAggregatesFilter<$PrismaModel> | Date | string
    _count?: NestedIntFilter<$PrismaModel>
    _min?: NestedDateTimeFilter<$PrismaModel>
    _max?: NestedDateTimeFilter<$PrismaModel>
  }

  export type StringNullableWithAggregatesFilter<$PrismaModel = never> = {
    equals?: string | StringFieldRefInput<$PrismaModel> | null
    in?: string[] | ListStringFieldRefInput<$PrismaModel> | null
    notIn?: string[] | ListStringFieldRefInput<$PrismaModel> | null
    lt?: string | StringFieldRefInput<$PrismaModel>
    lte?: string | StringFieldRefInput<$PrismaModel>
    gt?: string | StringFieldRefInput<$PrismaModel>
    gte?: string | StringFieldRefInput<$PrismaModel>
    contains?: string | StringFieldRefInput<$PrismaModel>
    startsWith?: string | StringFieldRefInput<$PrismaModel>
    endsWith?: string | StringFieldRefInput<$PrismaModel>
    mode?: QueryMode
    not?: NestedStringNullableWithAggregatesFilter<$PrismaModel> | string | null
    _count?: NestedIntNullableFilter<$PrismaModel>
    _min?: NestedStringNullableFilter<$PrismaModel>
    _max?: NestedStringNullableFilter<$PrismaModel>
  }

  export type DateTimeNullableWithAggregatesFilter<$PrismaModel = never> = {
    equals?: Date | string | DateTimeFieldRefInput<$PrismaModel> | null
    in?: Date[] | string[] | ListDateTimeFieldRefInput<$PrismaModel> | null
    notIn?: Date[] | string[] | ListDateTimeFieldRefInput<$PrismaModel> | null
    lt?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    lte?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    gt?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    gte?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    not?: NestedDateTimeNullableWithAggregatesFilter<$PrismaModel> | Date | string | null
    _count?: NestedIntNullableFilter<$PrismaModel>
    _min?: NestedDateTimeNullableFilter<$PrismaModel>
    _max?: NestedDateTimeNullableFilter<$PrismaModel>
  }

  export type EnumRoleWithAggregatesFilter<$PrismaModel = never> = {
    equals?: $Enums.Role | EnumRoleFieldRefInput<$PrismaModel>
    in?: $Enums.Role[] | ListEnumRoleFieldRefInput<$PrismaModel>
    notIn?: $Enums.Role[] | ListEnumRoleFieldRefInput<$PrismaModel>
    not?: NestedEnumRoleWithAggregatesFilter<$PrismaModel> | $Enums.Role
    _count?: NestedIntFilter<$PrismaModel>
    _min?: NestedEnumRoleFilter<$PrismaModel>
    _max?: NestedEnumRoleFilter<$PrismaModel>
  }

  export type IntNullableFilter<$PrismaModel = never> = {
    equals?: number | IntFieldRefInput<$PrismaModel> | null
    in?: number[] | ListIntFieldRefInput<$PrismaModel> | null
    notIn?: number[] | ListIntFieldRefInput<$PrismaModel> | null
    lt?: number | IntFieldRefInput<$PrismaModel>
    lte?: number | IntFieldRefInput<$PrismaModel>
    gt?: number | IntFieldRefInput<$PrismaModel>
    gte?: number | IntFieldRefInput<$PrismaModel>
    not?: NestedIntNullableFilter<$PrismaModel> | number | null
  }

  export type UsersNullableScalarRelationFilter = {
    is?: UsersWhereInput | null
    isNot?: UsersWhereInput | null
  }

  export type UsersListRelationFilter = {
    every?: UsersWhereInput
    some?: UsersWhereInput
    none?: UsersWhereInput
  }

  export type UsersOrderByRelationAggregateInput = {
    _count?: SortOrder
  }

  export type InstituicaoEspiritaCountOrderByAggregateInput = {
    id?: SortOrder
    nome?: SortOrder
    nome_CNPJ?: SortOrder
    estado?: SortOrder
    cidade?: SortOrder
    bairro?: SortOrder
    logradouro?: SortOrder
    numero?: SortOrder
    complemento?: SortOrder
    telefone?: SortOrder
    email?: SortOrder
    createdAt?: SortOrder
    updatedAt?: SortOrder
    criadoPorId?: SortOrder
    sigla?: SortOrder
    CEU?: SortOrder
    dia?: SortOrder
    horario?: SortOrder
    atualizadoPorId?: SortOrder
    CNPJ?: SortOrder
  }

  export type InstituicaoEspiritaAvgOrderByAggregateInput = {
    id?: SortOrder
    criadoPorId?: SortOrder
    atualizadoPorId?: SortOrder
  }

  export type InstituicaoEspiritaMaxOrderByAggregateInput = {
    id?: SortOrder
    nome?: SortOrder
    nome_CNPJ?: SortOrder
    estado?: SortOrder
    cidade?: SortOrder
    bairro?: SortOrder
    logradouro?: SortOrder
    numero?: SortOrder
    complemento?: SortOrder
    telefone?: SortOrder
    email?: SortOrder
    createdAt?: SortOrder
    updatedAt?: SortOrder
    criadoPorId?: SortOrder
    sigla?: SortOrder
    CEU?: SortOrder
    dia?: SortOrder
    horario?: SortOrder
    atualizadoPorId?: SortOrder
    CNPJ?: SortOrder
  }

  export type InstituicaoEspiritaMinOrderByAggregateInput = {
    id?: SortOrder
    nome?: SortOrder
    nome_CNPJ?: SortOrder
    estado?: SortOrder
    cidade?: SortOrder
    bairro?: SortOrder
    logradouro?: SortOrder
    numero?: SortOrder
    complemento?: SortOrder
    telefone?: SortOrder
    email?: SortOrder
    createdAt?: SortOrder
    updatedAt?: SortOrder
    criadoPorId?: SortOrder
    sigla?: SortOrder
    CEU?: SortOrder
    dia?: SortOrder
    horario?: SortOrder
    atualizadoPorId?: SortOrder
    CNPJ?: SortOrder
  }

  export type InstituicaoEspiritaSumOrderByAggregateInput = {
    id?: SortOrder
    criadoPorId?: SortOrder
    atualizadoPorId?: SortOrder
  }

  export type IntNullableWithAggregatesFilter<$PrismaModel = never> = {
    equals?: number | IntFieldRefInput<$PrismaModel> | null
    in?: number[] | ListIntFieldRefInput<$PrismaModel> | null
    notIn?: number[] | ListIntFieldRefInput<$PrismaModel> | null
    lt?: number | IntFieldRefInput<$PrismaModel>
    lte?: number | IntFieldRefInput<$PrismaModel>
    gt?: number | IntFieldRefInput<$PrismaModel>
    gte?: number | IntFieldRefInput<$PrismaModel>
    not?: NestedIntNullableWithAggregatesFilter<$PrismaModel> | number | null
    _count?: NestedIntNullableFilter<$PrismaModel>
    _avg?: NestedFloatNullableFilter<$PrismaModel>
    _sum?: NestedIntNullableFilter<$PrismaModel>
    _min?: NestedIntNullableFilter<$PrismaModel>
    _max?: NestedIntNullableFilter<$PrismaModel>
  }

  export type FloatNullableFilter<$PrismaModel = never> = {
    equals?: number | FloatFieldRefInput<$PrismaModel> | null
    in?: number[] | ListFloatFieldRefInput<$PrismaModel> | null
    notIn?: number[] | ListFloatFieldRefInput<$PrismaModel> | null
    lt?: number | FloatFieldRefInput<$PrismaModel>
    lte?: number | FloatFieldRefInput<$PrismaModel>
    gt?: number | FloatFieldRefInput<$PrismaModel>
    gte?: number | FloatFieldRefInput<$PrismaModel>
    not?: NestedFloatNullableFilter<$PrismaModel> | number | null
  }

  export type EnumTipoParticipacaoFilter<$PrismaModel = never> = {
    equals?: $Enums.TipoParticipacao | EnumTipoParticipacaoFieldRefInput<$PrismaModel>
    in?: $Enums.TipoParticipacao[] | ListEnumTipoParticipacaoFieldRefInput<$PrismaModel>
    notIn?: $Enums.TipoParticipacao[] | ListEnumTipoParticipacaoFieldRefInput<$PrismaModel>
    not?: NestedEnumTipoParticipacaoFilter<$PrismaModel> | $Enums.TipoParticipacao
  }

  export type BoolNullableFilter<$PrismaModel = never> = {
    equals?: boolean | BooleanFieldRefInput<$PrismaModel> | null
    not?: NestedBoolNullableFilter<$PrismaModel> | boolean | null
  }

  export type InstituicaoEspiritaNullableScalarRelationFilter = {
    is?: InstituicaoEspiritaWhereInput | null
    isNot?: InstituicaoEspiritaWhereInput | null
  }

  export type Participante2025CountOrderByAggregateInput = {
    id?: SortOrder
    nomeCompleto?: SortOrder
    nomeCracha?: SortOrder
    cpf?: SortOrder
    nomeSocial?: SortOrder
    dataNascimento?: SortOrder
    sexo?: SortOrder
    email?: SortOrder
    telefone?: SortOrder
    nomeCompletoResponsavel?: SortOrder
    documentoResponsavel?: SortOrder
    telefoneResponsavel?: SortOrder
    linkPagamento?: SortOrder
    idade?: SortOrder
    valor?: SortOrder
    statusPagamento?: SortOrder
    tipoParticipacao?: SortOrder
    comissao?: SortOrder
    tamanhoCamisa?: SortOrder
    cep?: SortOrder
    estado?: SortOrder
    cidade?: SortOrder
    bairro?: SortOrder
    logradouro?: SortOrder
    numero?: SortOrder
    complemento?: SortOrder
    outroGenero?: SortOrder
    medicacao?: SortOrder
    alergia?: SortOrder
    outrasInformacoes?: SortOrder
    userId?: SortOrder
    createdAt?: SortOrder
    updatedAt?: SortOrder
    IE?: SortOrder
    instituicaoId?: SortOrder
    vegetariano?: SortOrder
    camisa?: SortOrder
    primeiraComejaca?: SortOrder
    deficienciaAuditiva?: SortOrder
    deficienciaAutismo?: SortOrder
    deficienciaIntelectual?: SortOrder
    deficienciaParalisiaCerebral?: SortOrder
    deficienciaVisual?: SortOrder
    deficienciaFisica?: SortOrder
    deficienciaOutra?: SortOrder
    deficienciaOutraDescricao?: SortOrder
    otherInstitution?: SortOrder
  }

  export type Participante2025AvgOrderByAggregateInput = {
    idade?: SortOrder
    valor?: SortOrder
    userId?: SortOrder
    instituicaoId?: SortOrder
  }

  export type Participante2025MaxOrderByAggregateInput = {
    id?: SortOrder
    nomeCompleto?: SortOrder
    nomeCracha?: SortOrder
    cpf?: SortOrder
    nomeSocial?: SortOrder
    dataNascimento?: SortOrder
    sexo?: SortOrder
    email?: SortOrder
    telefone?: SortOrder
    nomeCompletoResponsavel?: SortOrder
    documentoResponsavel?: SortOrder
    telefoneResponsavel?: SortOrder
    linkPagamento?: SortOrder
    idade?: SortOrder
    valor?: SortOrder
    statusPagamento?: SortOrder
    tipoParticipacao?: SortOrder
    comissao?: SortOrder
    tamanhoCamisa?: SortOrder
    cep?: SortOrder
    estado?: SortOrder
    cidade?: SortOrder
    bairro?: SortOrder
    logradouro?: SortOrder
    numero?: SortOrder
    complemento?: SortOrder
    outroGenero?: SortOrder
    medicacao?: SortOrder
    alergia?: SortOrder
    outrasInformacoes?: SortOrder
    userId?: SortOrder
    createdAt?: SortOrder
    updatedAt?: SortOrder
    IE?: SortOrder
    instituicaoId?: SortOrder
    vegetariano?: SortOrder
    camisa?: SortOrder
    primeiraComejaca?: SortOrder
    deficienciaAuditiva?: SortOrder
    deficienciaAutismo?: SortOrder
    deficienciaIntelectual?: SortOrder
    deficienciaParalisiaCerebral?: SortOrder
    deficienciaVisual?: SortOrder
    deficienciaFisica?: SortOrder
    deficienciaOutra?: SortOrder
    deficienciaOutraDescricao?: SortOrder
    otherInstitution?: SortOrder
  }

  export type Participante2025MinOrderByAggregateInput = {
    id?: SortOrder
    nomeCompleto?: SortOrder
    nomeCracha?: SortOrder
    cpf?: SortOrder
    nomeSocial?: SortOrder
    dataNascimento?: SortOrder
    sexo?: SortOrder
    email?: SortOrder
    telefone?: SortOrder
    nomeCompletoResponsavel?: SortOrder
    documentoResponsavel?: SortOrder
    telefoneResponsavel?: SortOrder
    linkPagamento?: SortOrder
    idade?: SortOrder
    valor?: SortOrder
    statusPagamento?: SortOrder
    tipoParticipacao?: SortOrder
    comissao?: SortOrder
    tamanhoCamisa?: SortOrder
    cep?: SortOrder
    estado?: SortOrder
    cidade?: SortOrder
    bairro?: SortOrder
    logradouro?: SortOrder
    numero?: SortOrder
    complemento?: SortOrder
    outroGenero?: SortOrder
    medicacao?: SortOrder
    alergia?: SortOrder
    outrasInformacoes?: SortOrder
    userId?: SortOrder
    createdAt?: SortOrder
    updatedAt?: SortOrder
    IE?: SortOrder
    instituicaoId?: SortOrder
    vegetariano?: SortOrder
    camisa?: SortOrder
    primeiraComejaca?: SortOrder
    deficienciaAuditiva?: SortOrder
    deficienciaAutismo?: SortOrder
    deficienciaIntelectual?: SortOrder
    deficienciaParalisiaCerebral?: SortOrder
    deficienciaVisual?: SortOrder
    deficienciaFisica?: SortOrder
    deficienciaOutra?: SortOrder
    deficienciaOutraDescricao?: SortOrder
    otherInstitution?: SortOrder
  }

  export type Participante2025SumOrderByAggregateInput = {
    idade?: SortOrder
    valor?: SortOrder
    userId?: SortOrder
    instituicaoId?: SortOrder
  }

  export type FloatNullableWithAggregatesFilter<$PrismaModel = never> = {
    equals?: number | FloatFieldRefInput<$PrismaModel> | null
    in?: number[] | ListFloatFieldRefInput<$PrismaModel> | null
    notIn?: number[] | ListFloatFieldRefInput<$PrismaModel> | null
    lt?: number | FloatFieldRefInput<$PrismaModel>
    lte?: number | FloatFieldRefInput<$PrismaModel>
    gt?: number | FloatFieldRefInput<$PrismaModel>
    gte?: number | FloatFieldRefInput<$PrismaModel>
    not?: NestedFloatNullableWithAggregatesFilter<$PrismaModel> | number | null
    _count?: NestedIntNullableFilter<$PrismaModel>
    _avg?: NestedFloatNullableFilter<$PrismaModel>
    _sum?: NestedFloatNullableFilter<$PrismaModel>
    _min?: NestedFloatNullableFilter<$PrismaModel>
    _max?: NestedFloatNullableFilter<$PrismaModel>
  }

  export type EnumTipoParticipacaoWithAggregatesFilter<$PrismaModel = never> = {
    equals?: $Enums.TipoParticipacao | EnumTipoParticipacaoFieldRefInput<$PrismaModel>
    in?: $Enums.TipoParticipacao[] | ListEnumTipoParticipacaoFieldRefInput<$PrismaModel>
    notIn?: $Enums.TipoParticipacao[] | ListEnumTipoParticipacaoFieldRefInput<$PrismaModel>
    not?: NestedEnumTipoParticipacaoWithAggregatesFilter<$PrismaModel> | $Enums.TipoParticipacao
    _count?: NestedIntFilter<$PrismaModel>
    _min?: NestedEnumTipoParticipacaoFilter<$PrismaModel>
    _max?: NestedEnumTipoParticipacaoFilter<$PrismaModel>
  }

  export type BoolNullableWithAggregatesFilter<$PrismaModel = never> = {
    equals?: boolean | BooleanFieldRefInput<$PrismaModel> | null
    not?: NestedBoolNullableWithAggregatesFilter<$PrismaModel> | boolean | null
    _count?: NestedIntNullableFilter<$PrismaModel>
    _min?: NestedBoolNullableFilter<$PrismaModel>
    _max?: NestedBoolNullableFilter<$PrismaModel>
  }

  export type UsersScalarRelationFilter = {
    is?: UsersWhereInput
    isNot?: UsersWhereInput
  }

  export type PasswordResetTokenCountOrderByAggregateInput = {
    id?: SortOrder
    token?: SortOrder
    userId?: SortOrder
    expiresAt?: SortOrder
    createdAt?: SortOrder
  }

  export type PasswordResetTokenAvgOrderByAggregateInput = {
    id?: SortOrder
    userId?: SortOrder
  }

  export type PasswordResetTokenMaxOrderByAggregateInput = {
    id?: SortOrder
    token?: SortOrder
    userId?: SortOrder
    expiresAt?: SortOrder
    createdAt?: SortOrder
  }

  export type PasswordResetTokenMinOrderByAggregateInput = {
    id?: SortOrder
    token?: SortOrder
    userId?: SortOrder
    expiresAt?: SortOrder
    createdAt?: SortOrder
  }

  export type PasswordResetTokenSumOrderByAggregateInput = {
    id?: SortOrder
    userId?: SortOrder
  }

  export type InstituicaoEspiritaCreateNestedManyWithoutAtualizadoPorInput = {
    create?: XOR<InstituicaoEspiritaCreateWithoutAtualizadoPorInput, InstituicaoEspiritaUncheckedCreateWithoutAtualizadoPorInput> | InstituicaoEspiritaCreateWithoutAtualizadoPorInput[] | InstituicaoEspiritaUncheckedCreateWithoutAtualizadoPorInput[]
    connectOrCreate?: InstituicaoEspiritaCreateOrConnectWithoutAtualizadoPorInput | InstituicaoEspiritaCreateOrConnectWithoutAtualizadoPorInput[]
    createMany?: InstituicaoEspiritaCreateManyAtualizadoPorInputEnvelope
    connect?: InstituicaoEspiritaWhereUniqueInput | InstituicaoEspiritaWhereUniqueInput[]
  }

  export type InstituicaoEspiritaCreateNestedManyWithoutCriadoPorInput = {
    create?: XOR<InstituicaoEspiritaCreateWithoutCriadoPorInput, InstituicaoEspiritaUncheckedCreateWithoutCriadoPorInput> | InstituicaoEspiritaCreateWithoutCriadoPorInput[] | InstituicaoEspiritaUncheckedCreateWithoutCriadoPorInput[]
    connectOrCreate?: InstituicaoEspiritaCreateOrConnectWithoutCriadoPorInput | InstituicaoEspiritaCreateOrConnectWithoutCriadoPorInput[]
    createMany?: InstituicaoEspiritaCreateManyCriadoPorInputEnvelope
    connect?: InstituicaoEspiritaWhereUniqueInput | InstituicaoEspiritaWhereUniqueInput[]
  }

  export type Participante2025CreateNestedManyWithoutUserInput = {
    create?: XOR<Participante2025CreateWithoutUserInput, Participante2025UncheckedCreateWithoutUserInput> | Participante2025CreateWithoutUserInput[] | Participante2025UncheckedCreateWithoutUserInput[]
    connectOrCreate?: Participante2025CreateOrConnectWithoutUserInput | Participante2025CreateOrConnectWithoutUserInput[]
    createMany?: Participante2025CreateManyUserInputEnvelope
    connect?: Participante2025WhereUniqueInput | Participante2025WhereUniqueInput[]
  }

  export type InstituicaoEspiritaCreateNestedManyWithoutUsersInput = {
    create?: XOR<InstituicaoEspiritaCreateWithoutUsersInput, InstituicaoEspiritaUncheckedCreateWithoutUsersInput> | InstituicaoEspiritaCreateWithoutUsersInput[] | InstituicaoEspiritaUncheckedCreateWithoutUsersInput[]
    connectOrCreate?: InstituicaoEspiritaCreateOrConnectWithoutUsersInput | InstituicaoEspiritaCreateOrConnectWithoutUsersInput[]
    connect?: InstituicaoEspiritaWhereUniqueInput | InstituicaoEspiritaWhereUniqueInput[]
  }

  export type PasswordResetTokenCreateNestedManyWithoutUserInput = {
    create?: XOR<PasswordResetTokenCreateWithoutUserInput, PasswordResetTokenUncheckedCreateWithoutUserInput> | PasswordResetTokenCreateWithoutUserInput[] | PasswordResetTokenUncheckedCreateWithoutUserInput[]
    connectOrCreate?: PasswordResetTokenCreateOrConnectWithoutUserInput | PasswordResetTokenCreateOrConnectWithoutUserInput[]
    createMany?: PasswordResetTokenCreateManyUserInputEnvelope
    connect?: PasswordResetTokenWhereUniqueInput | PasswordResetTokenWhereUniqueInput[]
  }

  export type InstituicaoEspiritaUncheckedCreateNestedManyWithoutAtualizadoPorInput = {
    create?: XOR<InstituicaoEspiritaCreateWithoutAtualizadoPorInput, InstituicaoEspiritaUncheckedCreateWithoutAtualizadoPorInput> | InstituicaoEspiritaCreateWithoutAtualizadoPorInput[] | InstituicaoEspiritaUncheckedCreateWithoutAtualizadoPorInput[]
    connectOrCreate?: InstituicaoEspiritaCreateOrConnectWithoutAtualizadoPorInput | InstituicaoEspiritaCreateOrConnectWithoutAtualizadoPorInput[]
    createMany?: InstituicaoEspiritaCreateManyAtualizadoPorInputEnvelope
    connect?: InstituicaoEspiritaWhereUniqueInput | InstituicaoEspiritaWhereUniqueInput[]
  }

  export type InstituicaoEspiritaUncheckedCreateNestedManyWithoutCriadoPorInput = {
    create?: XOR<InstituicaoEspiritaCreateWithoutCriadoPorInput, InstituicaoEspiritaUncheckedCreateWithoutCriadoPorInput> | InstituicaoEspiritaCreateWithoutCriadoPorInput[] | InstituicaoEspiritaUncheckedCreateWithoutCriadoPorInput[]
    connectOrCreate?: InstituicaoEspiritaCreateOrConnectWithoutCriadoPorInput | InstituicaoEspiritaCreateOrConnectWithoutCriadoPorInput[]
    createMany?: InstituicaoEspiritaCreateManyCriadoPorInputEnvelope
    connect?: InstituicaoEspiritaWhereUniqueInput | InstituicaoEspiritaWhereUniqueInput[]
  }

  export type Participante2025UncheckedCreateNestedManyWithoutUserInput = {
    create?: XOR<Participante2025CreateWithoutUserInput, Participante2025UncheckedCreateWithoutUserInput> | Participante2025CreateWithoutUserInput[] | Participante2025UncheckedCreateWithoutUserInput[]
    connectOrCreate?: Participante2025CreateOrConnectWithoutUserInput | Participante2025CreateOrConnectWithoutUserInput[]
    createMany?: Participante2025CreateManyUserInputEnvelope
    connect?: Participante2025WhereUniqueInput | Participante2025WhereUniqueInput[]
  }

  export type InstituicaoEspiritaUncheckedCreateNestedManyWithoutUsersInput = {
    create?: XOR<InstituicaoEspiritaCreateWithoutUsersInput, InstituicaoEspiritaUncheckedCreateWithoutUsersInput> | InstituicaoEspiritaCreateWithoutUsersInput[] | InstituicaoEspiritaUncheckedCreateWithoutUsersInput[]
    connectOrCreate?: InstituicaoEspiritaCreateOrConnectWithoutUsersInput | InstituicaoEspiritaCreateOrConnectWithoutUsersInput[]
    connect?: InstituicaoEspiritaWhereUniqueInput | InstituicaoEspiritaWhereUniqueInput[]
  }

  export type PasswordResetTokenUncheckedCreateNestedManyWithoutUserInput = {
    create?: XOR<PasswordResetTokenCreateWithoutUserInput, PasswordResetTokenUncheckedCreateWithoutUserInput> | PasswordResetTokenCreateWithoutUserInput[] | PasswordResetTokenUncheckedCreateWithoutUserInput[]
    connectOrCreate?: PasswordResetTokenCreateOrConnectWithoutUserInput | PasswordResetTokenCreateOrConnectWithoutUserInput[]
    createMany?: PasswordResetTokenCreateManyUserInputEnvelope
    connect?: PasswordResetTokenWhereUniqueInput | PasswordResetTokenWhereUniqueInput[]
  }

  export type StringFieldUpdateOperationsInput = {
    set?: string
  }

  export type BoolFieldUpdateOperationsInput = {
    set?: boolean
  }

  export type DateTimeFieldUpdateOperationsInput = {
    set?: Date | string
  }

  export type NullableStringFieldUpdateOperationsInput = {
    set?: string | null
  }

  export type NullableDateTimeFieldUpdateOperationsInput = {
    set?: Date | string | null
  }

  export type EnumRoleFieldUpdateOperationsInput = {
    set?: $Enums.Role
  }

  export type IntFieldUpdateOperationsInput = {
    set?: number
    increment?: number
    decrement?: number
    multiply?: number
    divide?: number
  }

  export type InstituicaoEspiritaUpdateManyWithoutAtualizadoPorNestedInput = {
    create?: XOR<InstituicaoEspiritaCreateWithoutAtualizadoPorInput, InstituicaoEspiritaUncheckedCreateWithoutAtualizadoPorInput> | InstituicaoEspiritaCreateWithoutAtualizadoPorInput[] | InstituicaoEspiritaUncheckedCreateWithoutAtualizadoPorInput[]
    connectOrCreate?: InstituicaoEspiritaCreateOrConnectWithoutAtualizadoPorInput | InstituicaoEspiritaCreateOrConnectWithoutAtualizadoPorInput[]
    upsert?: InstituicaoEspiritaUpsertWithWhereUniqueWithoutAtualizadoPorInput | InstituicaoEspiritaUpsertWithWhereUniqueWithoutAtualizadoPorInput[]
    createMany?: InstituicaoEspiritaCreateManyAtualizadoPorInputEnvelope
    set?: InstituicaoEspiritaWhereUniqueInput | InstituicaoEspiritaWhereUniqueInput[]
    disconnect?: InstituicaoEspiritaWhereUniqueInput | InstituicaoEspiritaWhereUniqueInput[]
    delete?: InstituicaoEspiritaWhereUniqueInput | InstituicaoEspiritaWhereUniqueInput[]
    connect?: InstituicaoEspiritaWhereUniqueInput | InstituicaoEspiritaWhereUniqueInput[]
    update?: InstituicaoEspiritaUpdateWithWhereUniqueWithoutAtualizadoPorInput | InstituicaoEspiritaUpdateWithWhereUniqueWithoutAtualizadoPorInput[]
    updateMany?: InstituicaoEspiritaUpdateManyWithWhereWithoutAtualizadoPorInput | InstituicaoEspiritaUpdateManyWithWhereWithoutAtualizadoPorInput[]
    deleteMany?: InstituicaoEspiritaScalarWhereInput | InstituicaoEspiritaScalarWhereInput[]
  }

  export type InstituicaoEspiritaUpdateManyWithoutCriadoPorNestedInput = {
    create?: XOR<InstituicaoEspiritaCreateWithoutCriadoPorInput, InstituicaoEspiritaUncheckedCreateWithoutCriadoPorInput> | InstituicaoEspiritaCreateWithoutCriadoPorInput[] | InstituicaoEspiritaUncheckedCreateWithoutCriadoPorInput[]
    connectOrCreate?: InstituicaoEspiritaCreateOrConnectWithoutCriadoPorInput | InstituicaoEspiritaCreateOrConnectWithoutCriadoPorInput[]
    upsert?: InstituicaoEspiritaUpsertWithWhereUniqueWithoutCriadoPorInput | InstituicaoEspiritaUpsertWithWhereUniqueWithoutCriadoPorInput[]
    createMany?: InstituicaoEspiritaCreateManyCriadoPorInputEnvelope
    set?: InstituicaoEspiritaWhereUniqueInput | InstituicaoEspiritaWhereUniqueInput[]
    disconnect?: InstituicaoEspiritaWhereUniqueInput | InstituicaoEspiritaWhereUniqueInput[]
    delete?: InstituicaoEspiritaWhereUniqueInput | InstituicaoEspiritaWhereUniqueInput[]
    connect?: InstituicaoEspiritaWhereUniqueInput | InstituicaoEspiritaWhereUniqueInput[]
    update?: InstituicaoEspiritaUpdateWithWhereUniqueWithoutCriadoPorInput | InstituicaoEspiritaUpdateWithWhereUniqueWithoutCriadoPorInput[]
    updateMany?: InstituicaoEspiritaUpdateManyWithWhereWithoutCriadoPorInput | InstituicaoEspiritaUpdateManyWithWhereWithoutCriadoPorInput[]
    deleteMany?: InstituicaoEspiritaScalarWhereInput | InstituicaoEspiritaScalarWhereInput[]
  }

  export type Participante2025UpdateManyWithoutUserNestedInput = {
    create?: XOR<Participante2025CreateWithoutUserInput, Participante2025UncheckedCreateWithoutUserInput> | Participante2025CreateWithoutUserInput[] | Participante2025UncheckedCreateWithoutUserInput[]
    connectOrCreate?: Participante2025CreateOrConnectWithoutUserInput | Participante2025CreateOrConnectWithoutUserInput[]
    upsert?: Participante2025UpsertWithWhereUniqueWithoutUserInput | Participante2025UpsertWithWhereUniqueWithoutUserInput[]
    createMany?: Participante2025CreateManyUserInputEnvelope
    set?: Participante2025WhereUniqueInput | Participante2025WhereUniqueInput[]
    disconnect?: Participante2025WhereUniqueInput | Participante2025WhereUniqueInput[]
    delete?: Participante2025WhereUniqueInput | Participante2025WhereUniqueInput[]
    connect?: Participante2025WhereUniqueInput | Participante2025WhereUniqueInput[]
    update?: Participante2025UpdateWithWhereUniqueWithoutUserInput | Participante2025UpdateWithWhereUniqueWithoutUserInput[]
    updateMany?: Participante2025UpdateManyWithWhereWithoutUserInput | Participante2025UpdateManyWithWhereWithoutUserInput[]
    deleteMany?: Participante2025ScalarWhereInput | Participante2025ScalarWhereInput[]
  }

  export type InstituicaoEspiritaUpdateManyWithoutUsersNestedInput = {
    create?: XOR<InstituicaoEspiritaCreateWithoutUsersInput, InstituicaoEspiritaUncheckedCreateWithoutUsersInput> | InstituicaoEspiritaCreateWithoutUsersInput[] | InstituicaoEspiritaUncheckedCreateWithoutUsersInput[]
    connectOrCreate?: InstituicaoEspiritaCreateOrConnectWithoutUsersInput | InstituicaoEspiritaCreateOrConnectWithoutUsersInput[]
    upsert?: InstituicaoEspiritaUpsertWithWhereUniqueWithoutUsersInput | InstituicaoEspiritaUpsertWithWhereUniqueWithoutUsersInput[]
    set?: InstituicaoEspiritaWhereUniqueInput | InstituicaoEspiritaWhereUniqueInput[]
    disconnect?: InstituicaoEspiritaWhereUniqueInput | InstituicaoEspiritaWhereUniqueInput[]
    delete?: InstituicaoEspiritaWhereUniqueInput | InstituicaoEspiritaWhereUniqueInput[]
    connect?: InstituicaoEspiritaWhereUniqueInput | InstituicaoEspiritaWhereUniqueInput[]
    update?: InstituicaoEspiritaUpdateWithWhereUniqueWithoutUsersInput | InstituicaoEspiritaUpdateWithWhereUniqueWithoutUsersInput[]
    updateMany?: InstituicaoEspiritaUpdateManyWithWhereWithoutUsersInput | InstituicaoEspiritaUpdateManyWithWhereWithoutUsersInput[]
    deleteMany?: InstituicaoEspiritaScalarWhereInput | InstituicaoEspiritaScalarWhereInput[]
  }

  export type PasswordResetTokenUpdateManyWithoutUserNestedInput = {
    create?: XOR<PasswordResetTokenCreateWithoutUserInput, PasswordResetTokenUncheckedCreateWithoutUserInput> | PasswordResetTokenCreateWithoutUserInput[] | PasswordResetTokenUncheckedCreateWithoutUserInput[]
    connectOrCreate?: PasswordResetTokenCreateOrConnectWithoutUserInput | PasswordResetTokenCreateOrConnectWithoutUserInput[]
    upsert?: PasswordResetTokenUpsertWithWhereUniqueWithoutUserInput | PasswordResetTokenUpsertWithWhereUniqueWithoutUserInput[]
    createMany?: PasswordResetTokenCreateManyUserInputEnvelope
    set?: PasswordResetTokenWhereUniqueInput | PasswordResetTokenWhereUniqueInput[]
    disconnect?: PasswordResetTokenWhereUniqueInput | PasswordResetTokenWhereUniqueInput[]
    delete?: PasswordResetTokenWhereUniqueInput | PasswordResetTokenWhereUniqueInput[]
    connect?: PasswordResetTokenWhereUniqueInput | PasswordResetTokenWhereUniqueInput[]
    update?: PasswordResetTokenUpdateWithWhereUniqueWithoutUserInput | PasswordResetTokenUpdateWithWhereUniqueWithoutUserInput[]
    updateMany?: PasswordResetTokenUpdateManyWithWhereWithoutUserInput | PasswordResetTokenUpdateManyWithWhereWithoutUserInput[]
    deleteMany?: PasswordResetTokenScalarWhereInput | PasswordResetTokenScalarWhereInput[]
  }

  export type InstituicaoEspiritaUncheckedUpdateManyWithoutAtualizadoPorNestedInput = {
    create?: XOR<InstituicaoEspiritaCreateWithoutAtualizadoPorInput, InstituicaoEspiritaUncheckedCreateWithoutAtualizadoPorInput> | InstituicaoEspiritaCreateWithoutAtualizadoPorInput[] | InstituicaoEspiritaUncheckedCreateWithoutAtualizadoPorInput[]
    connectOrCreate?: InstituicaoEspiritaCreateOrConnectWithoutAtualizadoPorInput | InstituicaoEspiritaCreateOrConnectWithoutAtualizadoPorInput[]
    upsert?: InstituicaoEspiritaUpsertWithWhereUniqueWithoutAtualizadoPorInput | InstituicaoEspiritaUpsertWithWhereUniqueWithoutAtualizadoPorInput[]
    createMany?: InstituicaoEspiritaCreateManyAtualizadoPorInputEnvelope
    set?: InstituicaoEspiritaWhereUniqueInput | InstituicaoEspiritaWhereUniqueInput[]
    disconnect?: InstituicaoEspiritaWhereUniqueInput | InstituicaoEspiritaWhereUniqueInput[]
    delete?: InstituicaoEspiritaWhereUniqueInput | InstituicaoEspiritaWhereUniqueInput[]
    connect?: InstituicaoEspiritaWhereUniqueInput | InstituicaoEspiritaWhereUniqueInput[]
    update?: InstituicaoEspiritaUpdateWithWhereUniqueWithoutAtualizadoPorInput | InstituicaoEspiritaUpdateWithWhereUniqueWithoutAtualizadoPorInput[]
    updateMany?: InstituicaoEspiritaUpdateManyWithWhereWithoutAtualizadoPorInput | InstituicaoEspiritaUpdateManyWithWhereWithoutAtualizadoPorInput[]
    deleteMany?: InstituicaoEspiritaScalarWhereInput | InstituicaoEspiritaScalarWhereInput[]
  }

  export type InstituicaoEspiritaUncheckedUpdateManyWithoutCriadoPorNestedInput = {
    create?: XOR<InstituicaoEspiritaCreateWithoutCriadoPorInput, InstituicaoEspiritaUncheckedCreateWithoutCriadoPorInput> | InstituicaoEspiritaCreateWithoutCriadoPorInput[] | InstituicaoEspiritaUncheckedCreateWithoutCriadoPorInput[]
    connectOrCreate?: InstituicaoEspiritaCreateOrConnectWithoutCriadoPorInput | InstituicaoEspiritaCreateOrConnectWithoutCriadoPorInput[]
    upsert?: InstituicaoEspiritaUpsertWithWhereUniqueWithoutCriadoPorInput | InstituicaoEspiritaUpsertWithWhereUniqueWithoutCriadoPorInput[]
    createMany?: InstituicaoEspiritaCreateManyCriadoPorInputEnvelope
    set?: InstituicaoEspiritaWhereUniqueInput | InstituicaoEspiritaWhereUniqueInput[]
    disconnect?: InstituicaoEspiritaWhereUniqueInput | InstituicaoEspiritaWhereUniqueInput[]
    delete?: InstituicaoEspiritaWhereUniqueInput | InstituicaoEspiritaWhereUniqueInput[]
    connect?: InstituicaoEspiritaWhereUniqueInput | InstituicaoEspiritaWhereUniqueInput[]
    update?: InstituicaoEspiritaUpdateWithWhereUniqueWithoutCriadoPorInput | InstituicaoEspiritaUpdateWithWhereUniqueWithoutCriadoPorInput[]
    updateMany?: InstituicaoEspiritaUpdateManyWithWhereWithoutCriadoPorInput | InstituicaoEspiritaUpdateManyWithWhereWithoutCriadoPorInput[]
    deleteMany?: InstituicaoEspiritaScalarWhereInput | InstituicaoEspiritaScalarWhereInput[]
  }

  export type Participante2025UncheckedUpdateManyWithoutUserNestedInput = {
    create?: XOR<Participante2025CreateWithoutUserInput, Participante2025UncheckedCreateWithoutUserInput> | Participante2025CreateWithoutUserInput[] | Participante2025UncheckedCreateWithoutUserInput[]
    connectOrCreate?: Participante2025CreateOrConnectWithoutUserInput | Participante2025CreateOrConnectWithoutUserInput[]
    upsert?: Participante2025UpsertWithWhereUniqueWithoutUserInput | Participante2025UpsertWithWhereUniqueWithoutUserInput[]
    createMany?: Participante2025CreateManyUserInputEnvelope
    set?: Participante2025WhereUniqueInput | Participante2025WhereUniqueInput[]
    disconnect?: Participante2025WhereUniqueInput | Participante2025WhereUniqueInput[]
    delete?: Participante2025WhereUniqueInput | Participante2025WhereUniqueInput[]
    connect?: Participante2025WhereUniqueInput | Participante2025WhereUniqueInput[]
    update?: Participante2025UpdateWithWhereUniqueWithoutUserInput | Participante2025UpdateWithWhereUniqueWithoutUserInput[]
    updateMany?: Participante2025UpdateManyWithWhereWithoutUserInput | Participante2025UpdateManyWithWhereWithoutUserInput[]
    deleteMany?: Participante2025ScalarWhereInput | Participante2025ScalarWhereInput[]
  }

  export type InstituicaoEspiritaUncheckedUpdateManyWithoutUsersNestedInput = {
    create?: XOR<InstituicaoEspiritaCreateWithoutUsersInput, InstituicaoEspiritaUncheckedCreateWithoutUsersInput> | InstituicaoEspiritaCreateWithoutUsersInput[] | InstituicaoEspiritaUncheckedCreateWithoutUsersInput[]
    connectOrCreate?: InstituicaoEspiritaCreateOrConnectWithoutUsersInput | InstituicaoEspiritaCreateOrConnectWithoutUsersInput[]
    upsert?: InstituicaoEspiritaUpsertWithWhereUniqueWithoutUsersInput | InstituicaoEspiritaUpsertWithWhereUniqueWithoutUsersInput[]
    set?: InstituicaoEspiritaWhereUniqueInput | InstituicaoEspiritaWhereUniqueInput[]
    disconnect?: InstituicaoEspiritaWhereUniqueInput | InstituicaoEspiritaWhereUniqueInput[]
    delete?: InstituicaoEspiritaWhereUniqueInput | InstituicaoEspiritaWhereUniqueInput[]
    connect?: InstituicaoEspiritaWhereUniqueInput | InstituicaoEspiritaWhereUniqueInput[]
    update?: InstituicaoEspiritaUpdateWithWhereUniqueWithoutUsersInput | InstituicaoEspiritaUpdateWithWhereUniqueWithoutUsersInput[]
    updateMany?: InstituicaoEspiritaUpdateManyWithWhereWithoutUsersInput | InstituicaoEspiritaUpdateManyWithWhereWithoutUsersInput[]
    deleteMany?: InstituicaoEspiritaScalarWhereInput | InstituicaoEspiritaScalarWhereInput[]
  }

  export type PasswordResetTokenUncheckedUpdateManyWithoutUserNestedInput = {
    create?: XOR<PasswordResetTokenCreateWithoutUserInput, PasswordResetTokenUncheckedCreateWithoutUserInput> | PasswordResetTokenCreateWithoutUserInput[] | PasswordResetTokenUncheckedCreateWithoutUserInput[]
    connectOrCreate?: PasswordResetTokenCreateOrConnectWithoutUserInput | PasswordResetTokenCreateOrConnectWithoutUserInput[]
    upsert?: PasswordResetTokenUpsertWithWhereUniqueWithoutUserInput | PasswordResetTokenUpsertWithWhereUniqueWithoutUserInput[]
    createMany?: PasswordResetTokenCreateManyUserInputEnvelope
    set?: PasswordResetTokenWhereUniqueInput | PasswordResetTokenWhereUniqueInput[]
    disconnect?: PasswordResetTokenWhereUniqueInput | PasswordResetTokenWhereUniqueInput[]
    delete?: PasswordResetTokenWhereUniqueInput | PasswordResetTokenWhereUniqueInput[]
    connect?: PasswordResetTokenWhereUniqueInput | PasswordResetTokenWhereUniqueInput[]
    update?: PasswordResetTokenUpdateWithWhereUniqueWithoutUserInput | PasswordResetTokenUpdateWithWhereUniqueWithoutUserInput[]
    updateMany?: PasswordResetTokenUpdateManyWithWhereWithoutUserInput | PasswordResetTokenUpdateManyWithWhereWithoutUserInput[]
    deleteMany?: PasswordResetTokenScalarWhereInput | PasswordResetTokenScalarWhereInput[]
  }

  export type UsersCreateNestedOneWithoutInstituicoesAtualizadasInput = {
    create?: XOR<UsersCreateWithoutInstituicoesAtualizadasInput, UsersUncheckedCreateWithoutInstituicoesAtualizadasInput>
    connectOrCreate?: UsersCreateOrConnectWithoutInstituicoesAtualizadasInput
    connect?: UsersWhereUniqueInput
  }

  export type UsersCreateNestedOneWithoutInstituicoesCriadasInput = {
    create?: XOR<UsersCreateWithoutInstituicoesCriadasInput, UsersUncheckedCreateWithoutInstituicoesCriadasInput>
    connectOrCreate?: UsersCreateOrConnectWithoutInstituicoesCriadasInput
    connect?: UsersWhereUniqueInput
  }

  export type Participante2025CreateNestedManyWithoutInstituicaoInput = {
    create?: XOR<Participante2025CreateWithoutInstituicaoInput, Participante2025UncheckedCreateWithoutInstituicaoInput> | Participante2025CreateWithoutInstituicaoInput[] | Participante2025UncheckedCreateWithoutInstituicaoInput[]
    connectOrCreate?: Participante2025CreateOrConnectWithoutInstituicaoInput | Participante2025CreateOrConnectWithoutInstituicaoInput[]
    createMany?: Participante2025CreateManyInstituicaoInputEnvelope
    connect?: Participante2025WhereUniqueInput | Participante2025WhereUniqueInput[]
  }

  export type UsersCreateNestedManyWithoutInstituicoesInput = {
    create?: XOR<UsersCreateWithoutInstituicoesInput, UsersUncheckedCreateWithoutInstituicoesInput> | UsersCreateWithoutInstituicoesInput[] | UsersUncheckedCreateWithoutInstituicoesInput[]
    connectOrCreate?: UsersCreateOrConnectWithoutInstituicoesInput | UsersCreateOrConnectWithoutInstituicoesInput[]
    connect?: UsersWhereUniqueInput | UsersWhereUniqueInput[]
  }

  export type Participante2025UncheckedCreateNestedManyWithoutInstituicaoInput = {
    create?: XOR<Participante2025CreateWithoutInstituicaoInput, Participante2025UncheckedCreateWithoutInstituicaoInput> | Participante2025CreateWithoutInstituicaoInput[] | Participante2025UncheckedCreateWithoutInstituicaoInput[]
    connectOrCreate?: Participante2025CreateOrConnectWithoutInstituicaoInput | Participante2025CreateOrConnectWithoutInstituicaoInput[]
    createMany?: Participante2025CreateManyInstituicaoInputEnvelope
    connect?: Participante2025WhereUniqueInput | Participante2025WhereUniqueInput[]
  }

  export type UsersUncheckedCreateNestedManyWithoutInstituicoesInput = {
    create?: XOR<UsersCreateWithoutInstituicoesInput, UsersUncheckedCreateWithoutInstituicoesInput> | UsersCreateWithoutInstituicoesInput[] | UsersUncheckedCreateWithoutInstituicoesInput[]
    connectOrCreate?: UsersCreateOrConnectWithoutInstituicoesInput | UsersCreateOrConnectWithoutInstituicoesInput[]
    connect?: UsersWhereUniqueInput | UsersWhereUniqueInput[]
  }

  export type UsersUpdateOneWithoutInstituicoesAtualizadasNestedInput = {
    create?: XOR<UsersCreateWithoutInstituicoesAtualizadasInput, UsersUncheckedCreateWithoutInstituicoesAtualizadasInput>
    connectOrCreate?: UsersCreateOrConnectWithoutInstituicoesAtualizadasInput
    upsert?: UsersUpsertWithoutInstituicoesAtualizadasInput
    disconnect?: UsersWhereInput | boolean
    delete?: UsersWhereInput | boolean
    connect?: UsersWhereUniqueInput
    update?: XOR<XOR<UsersUpdateToOneWithWhereWithoutInstituicoesAtualizadasInput, UsersUpdateWithoutInstituicoesAtualizadasInput>, UsersUncheckedUpdateWithoutInstituicoesAtualizadasInput>
  }

  export type UsersUpdateOneWithoutInstituicoesCriadasNestedInput = {
    create?: XOR<UsersCreateWithoutInstituicoesCriadasInput, UsersUncheckedCreateWithoutInstituicoesCriadasInput>
    connectOrCreate?: UsersCreateOrConnectWithoutInstituicoesCriadasInput
    upsert?: UsersUpsertWithoutInstituicoesCriadasInput
    disconnect?: UsersWhereInput | boolean
    delete?: UsersWhereInput | boolean
    connect?: UsersWhereUniqueInput
    update?: XOR<XOR<UsersUpdateToOneWithWhereWithoutInstituicoesCriadasInput, UsersUpdateWithoutInstituicoesCriadasInput>, UsersUncheckedUpdateWithoutInstituicoesCriadasInput>
  }

  export type Participante2025UpdateManyWithoutInstituicaoNestedInput = {
    create?: XOR<Participante2025CreateWithoutInstituicaoInput, Participante2025UncheckedCreateWithoutInstituicaoInput> | Participante2025CreateWithoutInstituicaoInput[] | Participante2025UncheckedCreateWithoutInstituicaoInput[]
    connectOrCreate?: Participante2025CreateOrConnectWithoutInstituicaoInput | Participante2025CreateOrConnectWithoutInstituicaoInput[]
    upsert?: Participante2025UpsertWithWhereUniqueWithoutInstituicaoInput | Participante2025UpsertWithWhereUniqueWithoutInstituicaoInput[]
    createMany?: Participante2025CreateManyInstituicaoInputEnvelope
    set?: Participante2025WhereUniqueInput | Participante2025WhereUniqueInput[]
    disconnect?: Participante2025WhereUniqueInput | Participante2025WhereUniqueInput[]
    delete?: Participante2025WhereUniqueInput | Participante2025WhereUniqueInput[]
    connect?: Participante2025WhereUniqueInput | Participante2025WhereUniqueInput[]
    update?: Participante2025UpdateWithWhereUniqueWithoutInstituicaoInput | Participante2025UpdateWithWhereUniqueWithoutInstituicaoInput[]
    updateMany?: Participante2025UpdateManyWithWhereWithoutInstituicaoInput | Participante2025UpdateManyWithWhereWithoutInstituicaoInput[]
    deleteMany?: Participante2025ScalarWhereInput | Participante2025ScalarWhereInput[]
  }

  export type UsersUpdateManyWithoutInstituicoesNestedInput = {
    create?: XOR<UsersCreateWithoutInstituicoesInput, UsersUncheckedCreateWithoutInstituicoesInput> | UsersCreateWithoutInstituicoesInput[] | UsersUncheckedCreateWithoutInstituicoesInput[]
    connectOrCreate?: UsersCreateOrConnectWithoutInstituicoesInput | UsersCreateOrConnectWithoutInstituicoesInput[]
    upsert?: UsersUpsertWithWhereUniqueWithoutInstituicoesInput | UsersUpsertWithWhereUniqueWithoutInstituicoesInput[]
    set?: UsersWhereUniqueInput | UsersWhereUniqueInput[]
    disconnect?: UsersWhereUniqueInput | UsersWhereUniqueInput[]
    delete?: UsersWhereUniqueInput | UsersWhereUniqueInput[]
    connect?: UsersWhereUniqueInput | UsersWhereUniqueInput[]
    update?: UsersUpdateWithWhereUniqueWithoutInstituicoesInput | UsersUpdateWithWhereUniqueWithoutInstituicoesInput[]
    updateMany?: UsersUpdateManyWithWhereWithoutInstituicoesInput | UsersUpdateManyWithWhereWithoutInstituicoesInput[]
    deleteMany?: UsersScalarWhereInput | UsersScalarWhereInput[]
  }

  export type NullableIntFieldUpdateOperationsInput = {
    set?: number | null
    increment?: number
    decrement?: number
    multiply?: number
    divide?: number
  }

  export type Participante2025UncheckedUpdateManyWithoutInstituicaoNestedInput = {
    create?: XOR<Participante2025CreateWithoutInstituicaoInput, Participante2025UncheckedCreateWithoutInstituicaoInput> | Participante2025CreateWithoutInstituicaoInput[] | Participante2025UncheckedCreateWithoutInstituicaoInput[]
    connectOrCreate?: Participante2025CreateOrConnectWithoutInstituicaoInput | Participante2025CreateOrConnectWithoutInstituicaoInput[]
    upsert?: Participante2025UpsertWithWhereUniqueWithoutInstituicaoInput | Participante2025UpsertWithWhereUniqueWithoutInstituicaoInput[]
    createMany?: Participante2025CreateManyInstituicaoInputEnvelope
    set?: Participante2025WhereUniqueInput | Participante2025WhereUniqueInput[]
    disconnect?: Participante2025WhereUniqueInput | Participante2025WhereUniqueInput[]
    delete?: Participante2025WhereUniqueInput | Participante2025WhereUniqueInput[]
    connect?: Participante2025WhereUniqueInput | Participante2025WhereUniqueInput[]
    update?: Participante2025UpdateWithWhereUniqueWithoutInstituicaoInput | Participante2025UpdateWithWhereUniqueWithoutInstituicaoInput[]
    updateMany?: Participante2025UpdateManyWithWhereWithoutInstituicaoInput | Participante2025UpdateManyWithWhereWithoutInstituicaoInput[]
    deleteMany?: Participante2025ScalarWhereInput | Participante2025ScalarWhereInput[]
  }

  export type UsersUncheckedUpdateManyWithoutInstituicoesNestedInput = {
    create?: XOR<UsersCreateWithoutInstituicoesInput, UsersUncheckedCreateWithoutInstituicoesInput> | UsersCreateWithoutInstituicoesInput[] | UsersUncheckedCreateWithoutInstituicoesInput[]
    connectOrCreate?: UsersCreateOrConnectWithoutInstituicoesInput | UsersCreateOrConnectWithoutInstituicoesInput[]
    upsert?: UsersUpsertWithWhereUniqueWithoutInstituicoesInput | UsersUpsertWithWhereUniqueWithoutInstituicoesInput[]
    set?: UsersWhereUniqueInput | UsersWhereUniqueInput[]
    disconnect?: UsersWhereUniqueInput | UsersWhereUniqueInput[]
    delete?: UsersWhereUniqueInput | UsersWhereUniqueInput[]
    connect?: UsersWhereUniqueInput | UsersWhereUniqueInput[]
    update?: UsersUpdateWithWhereUniqueWithoutInstituicoesInput | UsersUpdateWithWhereUniqueWithoutInstituicoesInput[]
    updateMany?: UsersUpdateManyWithWhereWithoutInstituicoesInput | UsersUpdateManyWithWhereWithoutInstituicoesInput[]
    deleteMany?: UsersScalarWhereInput | UsersScalarWhereInput[]
  }

  export type InstituicaoEspiritaCreateNestedOneWithoutParticipante2025Input = {
    create?: XOR<InstituicaoEspiritaCreateWithoutParticipante2025Input, InstituicaoEspiritaUncheckedCreateWithoutParticipante2025Input>
    connectOrCreate?: InstituicaoEspiritaCreateOrConnectWithoutParticipante2025Input
    connect?: InstituicaoEspiritaWhereUniqueInput
  }

  export type UsersCreateNestedOneWithoutParticipante2025Input = {
    create?: XOR<UsersCreateWithoutParticipante2025Input, UsersUncheckedCreateWithoutParticipante2025Input>
    connectOrCreate?: UsersCreateOrConnectWithoutParticipante2025Input
    connect?: UsersWhereUniqueInput
  }

  export type NullableFloatFieldUpdateOperationsInput = {
    set?: number | null
    increment?: number
    decrement?: number
    multiply?: number
    divide?: number
  }

  export type EnumTipoParticipacaoFieldUpdateOperationsInput = {
    set?: $Enums.TipoParticipacao
  }

  export type NullableBoolFieldUpdateOperationsInput = {
    set?: boolean | null
  }

  export type InstituicaoEspiritaUpdateOneWithoutParticipante2025NestedInput = {
    create?: XOR<InstituicaoEspiritaCreateWithoutParticipante2025Input, InstituicaoEspiritaUncheckedCreateWithoutParticipante2025Input>
    connectOrCreate?: InstituicaoEspiritaCreateOrConnectWithoutParticipante2025Input
    upsert?: InstituicaoEspiritaUpsertWithoutParticipante2025Input
    disconnect?: InstituicaoEspiritaWhereInput | boolean
    delete?: InstituicaoEspiritaWhereInput | boolean
    connect?: InstituicaoEspiritaWhereUniqueInput
    update?: XOR<XOR<InstituicaoEspiritaUpdateToOneWithWhereWithoutParticipante2025Input, InstituicaoEspiritaUpdateWithoutParticipante2025Input>, InstituicaoEspiritaUncheckedUpdateWithoutParticipante2025Input>
  }

  export type UsersUpdateOneWithoutParticipante2025NestedInput = {
    create?: XOR<UsersCreateWithoutParticipante2025Input, UsersUncheckedCreateWithoutParticipante2025Input>
    connectOrCreate?: UsersCreateOrConnectWithoutParticipante2025Input
    upsert?: UsersUpsertWithoutParticipante2025Input
    disconnect?: UsersWhereInput | boolean
    delete?: UsersWhereInput | boolean
    connect?: UsersWhereUniqueInput
    update?: XOR<XOR<UsersUpdateToOneWithWhereWithoutParticipante2025Input, UsersUpdateWithoutParticipante2025Input>, UsersUncheckedUpdateWithoutParticipante2025Input>
  }

  export type UsersCreateNestedOneWithoutPasswordResetTokensInput = {
    create?: XOR<UsersCreateWithoutPasswordResetTokensInput, UsersUncheckedCreateWithoutPasswordResetTokensInput>
    connectOrCreate?: UsersCreateOrConnectWithoutPasswordResetTokensInput
    connect?: UsersWhereUniqueInput
  }

  export type UsersUpdateOneRequiredWithoutPasswordResetTokensNestedInput = {
    create?: XOR<UsersCreateWithoutPasswordResetTokensInput, UsersUncheckedCreateWithoutPasswordResetTokensInput>
    connectOrCreate?: UsersCreateOrConnectWithoutPasswordResetTokensInput
    upsert?: UsersUpsertWithoutPasswordResetTokensInput
    connect?: UsersWhereUniqueInput
    update?: XOR<XOR<UsersUpdateToOneWithWhereWithoutPasswordResetTokensInput, UsersUpdateWithoutPasswordResetTokensInput>, UsersUncheckedUpdateWithoutPasswordResetTokensInput>
  }

  export type NestedIntFilter<$PrismaModel = never> = {
    equals?: number | IntFieldRefInput<$PrismaModel>
    in?: number[] | ListIntFieldRefInput<$PrismaModel>
    notIn?: number[] | ListIntFieldRefInput<$PrismaModel>
    lt?: number | IntFieldRefInput<$PrismaModel>
    lte?: number | IntFieldRefInput<$PrismaModel>
    gt?: number | IntFieldRefInput<$PrismaModel>
    gte?: number | IntFieldRefInput<$PrismaModel>
    not?: NestedIntFilter<$PrismaModel> | number
  }

  export type NestedStringFilter<$PrismaModel = never> = {
    equals?: string | StringFieldRefInput<$PrismaModel>
    in?: string[] | ListStringFieldRefInput<$PrismaModel>
    notIn?: string[] | ListStringFieldRefInput<$PrismaModel>
    lt?: string | StringFieldRefInput<$PrismaModel>
    lte?: string | StringFieldRefInput<$PrismaModel>
    gt?: string | StringFieldRefInput<$PrismaModel>
    gte?: string | StringFieldRefInput<$PrismaModel>
    contains?: string | StringFieldRefInput<$PrismaModel>
    startsWith?: string | StringFieldRefInput<$PrismaModel>
    endsWith?: string | StringFieldRefInput<$PrismaModel>
    not?: NestedStringFilter<$PrismaModel> | string
  }

  export type NestedBoolFilter<$PrismaModel = never> = {
    equals?: boolean | BooleanFieldRefInput<$PrismaModel>
    not?: NestedBoolFilter<$PrismaModel> | boolean
  }

  export type NestedDateTimeFilter<$PrismaModel = never> = {
    equals?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    in?: Date[] | string[] | ListDateTimeFieldRefInput<$PrismaModel>
    notIn?: Date[] | string[] | ListDateTimeFieldRefInput<$PrismaModel>
    lt?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    lte?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    gt?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    gte?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    not?: NestedDateTimeFilter<$PrismaModel> | Date | string
  }

  export type NestedStringNullableFilter<$PrismaModel = never> = {
    equals?: string | StringFieldRefInput<$PrismaModel> | null
    in?: string[] | ListStringFieldRefInput<$PrismaModel> | null
    notIn?: string[] | ListStringFieldRefInput<$PrismaModel> | null
    lt?: string | StringFieldRefInput<$PrismaModel>
    lte?: string | StringFieldRefInput<$PrismaModel>
    gt?: string | StringFieldRefInput<$PrismaModel>
    gte?: string | StringFieldRefInput<$PrismaModel>
    contains?: string | StringFieldRefInput<$PrismaModel>
    startsWith?: string | StringFieldRefInput<$PrismaModel>
    endsWith?: string | StringFieldRefInput<$PrismaModel>
    not?: NestedStringNullableFilter<$PrismaModel> | string | null
  }

  export type NestedDateTimeNullableFilter<$PrismaModel = never> = {
    equals?: Date | string | DateTimeFieldRefInput<$PrismaModel> | null
    in?: Date[] | string[] | ListDateTimeFieldRefInput<$PrismaModel> | null
    notIn?: Date[] | string[] | ListDateTimeFieldRefInput<$PrismaModel> | null
    lt?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    lte?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    gt?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    gte?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    not?: NestedDateTimeNullableFilter<$PrismaModel> | Date | string | null
  }

  export type NestedEnumRoleFilter<$PrismaModel = never> = {
    equals?: $Enums.Role | EnumRoleFieldRefInput<$PrismaModel>
    in?: $Enums.Role[] | ListEnumRoleFieldRefInput<$PrismaModel>
    notIn?: $Enums.Role[] | ListEnumRoleFieldRefInput<$PrismaModel>
    not?: NestedEnumRoleFilter<$PrismaModel> | $Enums.Role
  }

  export type NestedIntWithAggregatesFilter<$PrismaModel = never> = {
    equals?: number | IntFieldRefInput<$PrismaModel>
    in?: number[] | ListIntFieldRefInput<$PrismaModel>
    notIn?: number[] | ListIntFieldRefInput<$PrismaModel>
    lt?: number | IntFieldRefInput<$PrismaModel>
    lte?: number | IntFieldRefInput<$PrismaModel>
    gt?: number | IntFieldRefInput<$PrismaModel>
    gte?: number | IntFieldRefInput<$PrismaModel>
    not?: NestedIntWithAggregatesFilter<$PrismaModel> | number
    _count?: NestedIntFilter<$PrismaModel>
    _avg?: NestedFloatFilter<$PrismaModel>
    _sum?: NestedIntFilter<$PrismaModel>
    _min?: NestedIntFilter<$PrismaModel>
    _max?: NestedIntFilter<$PrismaModel>
  }

  export type NestedFloatFilter<$PrismaModel = never> = {
    equals?: number | FloatFieldRefInput<$PrismaModel>
    in?: number[] | ListFloatFieldRefInput<$PrismaModel>
    notIn?: number[] | ListFloatFieldRefInput<$PrismaModel>
    lt?: number | FloatFieldRefInput<$PrismaModel>
    lte?: number | FloatFieldRefInput<$PrismaModel>
    gt?: number | FloatFieldRefInput<$PrismaModel>
    gte?: number | FloatFieldRefInput<$PrismaModel>
    not?: NestedFloatFilter<$PrismaModel> | number
  }

  export type NestedStringWithAggregatesFilter<$PrismaModel = never> = {
    equals?: string | StringFieldRefInput<$PrismaModel>
    in?: string[] | ListStringFieldRefInput<$PrismaModel>
    notIn?: string[] | ListStringFieldRefInput<$PrismaModel>
    lt?: string | StringFieldRefInput<$PrismaModel>
    lte?: string | StringFieldRefInput<$PrismaModel>
    gt?: string | StringFieldRefInput<$PrismaModel>
    gte?: string | StringFieldRefInput<$PrismaModel>
    contains?: string | StringFieldRefInput<$PrismaModel>
    startsWith?: string | StringFieldRefInput<$PrismaModel>
    endsWith?: string | StringFieldRefInput<$PrismaModel>
    not?: NestedStringWithAggregatesFilter<$PrismaModel> | string
    _count?: NestedIntFilter<$PrismaModel>
    _min?: NestedStringFilter<$PrismaModel>
    _max?: NestedStringFilter<$PrismaModel>
  }

  export type NestedBoolWithAggregatesFilter<$PrismaModel = never> = {
    equals?: boolean | BooleanFieldRefInput<$PrismaModel>
    not?: NestedBoolWithAggregatesFilter<$PrismaModel> | boolean
    _count?: NestedIntFilter<$PrismaModel>
    _min?: NestedBoolFilter<$PrismaModel>
    _max?: NestedBoolFilter<$PrismaModel>
  }

  export type NestedDateTimeWithAggregatesFilter<$PrismaModel = never> = {
    equals?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    in?: Date[] | string[] | ListDateTimeFieldRefInput<$PrismaModel>
    notIn?: Date[] | string[] | ListDateTimeFieldRefInput<$PrismaModel>
    lt?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    lte?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    gt?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    gte?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    not?: NestedDateTimeWithAggregatesFilter<$PrismaModel> | Date | string
    _count?: NestedIntFilter<$PrismaModel>
    _min?: NestedDateTimeFilter<$PrismaModel>
    _max?: NestedDateTimeFilter<$PrismaModel>
  }

  export type NestedStringNullableWithAggregatesFilter<$PrismaModel = never> = {
    equals?: string | StringFieldRefInput<$PrismaModel> | null
    in?: string[] | ListStringFieldRefInput<$PrismaModel> | null
    notIn?: string[] | ListStringFieldRefInput<$PrismaModel> | null
    lt?: string | StringFieldRefInput<$PrismaModel>
    lte?: string | StringFieldRefInput<$PrismaModel>
    gt?: string | StringFieldRefInput<$PrismaModel>
    gte?: string | StringFieldRefInput<$PrismaModel>
    contains?: string | StringFieldRefInput<$PrismaModel>
    startsWith?: string | StringFieldRefInput<$PrismaModel>
    endsWith?: string | StringFieldRefInput<$PrismaModel>
    not?: NestedStringNullableWithAggregatesFilter<$PrismaModel> | string | null
    _count?: NestedIntNullableFilter<$PrismaModel>
    _min?: NestedStringNullableFilter<$PrismaModel>
    _max?: NestedStringNullableFilter<$PrismaModel>
  }

  export type NestedIntNullableFilter<$PrismaModel = never> = {
    equals?: number | IntFieldRefInput<$PrismaModel> | null
    in?: number[] | ListIntFieldRefInput<$PrismaModel> | null
    notIn?: number[] | ListIntFieldRefInput<$PrismaModel> | null
    lt?: number | IntFieldRefInput<$PrismaModel>
    lte?: number | IntFieldRefInput<$PrismaModel>
    gt?: number | IntFieldRefInput<$PrismaModel>
    gte?: number | IntFieldRefInput<$PrismaModel>
    not?: NestedIntNullableFilter<$PrismaModel> | number | null
  }

  export type NestedDateTimeNullableWithAggregatesFilter<$PrismaModel = never> = {
    equals?: Date | string | DateTimeFieldRefInput<$PrismaModel> | null
    in?: Date[] | string[] | ListDateTimeFieldRefInput<$PrismaModel> | null
    notIn?: Date[] | string[] | ListDateTimeFieldRefInput<$PrismaModel> | null
    lt?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    lte?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    gt?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    gte?: Date | string | DateTimeFieldRefInput<$PrismaModel>
    not?: NestedDateTimeNullableWithAggregatesFilter<$PrismaModel> | Date | string | null
    _count?: NestedIntNullableFilter<$PrismaModel>
    _min?: NestedDateTimeNullableFilter<$PrismaModel>
    _max?: NestedDateTimeNullableFilter<$PrismaModel>
  }

  export type NestedEnumRoleWithAggregatesFilter<$PrismaModel = never> = {
    equals?: $Enums.Role | EnumRoleFieldRefInput<$PrismaModel>
    in?: $Enums.Role[] | ListEnumRoleFieldRefInput<$PrismaModel>
    notIn?: $Enums.Role[] | ListEnumRoleFieldRefInput<$PrismaModel>
    not?: NestedEnumRoleWithAggregatesFilter<$PrismaModel> | $Enums.Role
    _count?: NestedIntFilter<$PrismaModel>
    _min?: NestedEnumRoleFilter<$PrismaModel>
    _max?: NestedEnumRoleFilter<$PrismaModel>
  }

  export type NestedIntNullableWithAggregatesFilter<$PrismaModel = never> = {
    equals?: number | IntFieldRefInput<$PrismaModel> | null
    in?: number[] | ListIntFieldRefInput<$PrismaModel> | null
    notIn?: number[] | ListIntFieldRefInput<$PrismaModel> | null
    lt?: number | IntFieldRefInput<$PrismaModel>
    lte?: number | IntFieldRefInput<$PrismaModel>
    gt?: number | IntFieldRefInput<$PrismaModel>
    gte?: number | IntFieldRefInput<$PrismaModel>
    not?: NestedIntNullableWithAggregatesFilter<$PrismaModel> | number | null
    _count?: NestedIntNullableFilter<$PrismaModel>
    _avg?: NestedFloatNullableFilter<$PrismaModel>
    _sum?: NestedIntNullableFilter<$PrismaModel>
    _min?: NestedIntNullableFilter<$PrismaModel>
    _max?: NestedIntNullableFilter<$PrismaModel>
  }

  export type NestedFloatNullableFilter<$PrismaModel = never> = {
    equals?: number | FloatFieldRefInput<$PrismaModel> | null
    in?: number[] | ListFloatFieldRefInput<$PrismaModel> | null
    notIn?: number[] | ListFloatFieldRefInput<$PrismaModel> | null
    lt?: number | FloatFieldRefInput<$PrismaModel>
    lte?: number | FloatFieldRefInput<$PrismaModel>
    gt?: number | FloatFieldRefInput<$PrismaModel>
    gte?: number | FloatFieldRefInput<$PrismaModel>
    not?: NestedFloatNullableFilter<$PrismaModel> | number | null
  }

  export type NestedEnumTipoParticipacaoFilter<$PrismaModel = never> = {
    equals?: $Enums.TipoParticipacao | EnumTipoParticipacaoFieldRefInput<$PrismaModel>
    in?: $Enums.TipoParticipacao[] | ListEnumTipoParticipacaoFieldRefInput<$PrismaModel>
    notIn?: $Enums.TipoParticipacao[] | ListEnumTipoParticipacaoFieldRefInput<$PrismaModel>
    not?: NestedEnumTipoParticipacaoFilter<$PrismaModel> | $Enums.TipoParticipacao
  }

  export type NestedBoolNullableFilter<$PrismaModel = never> = {
    equals?: boolean | BooleanFieldRefInput<$PrismaModel> | null
    not?: NestedBoolNullableFilter<$PrismaModel> | boolean | null
  }

  export type NestedFloatNullableWithAggregatesFilter<$PrismaModel = never> = {
    equals?: number | FloatFieldRefInput<$PrismaModel> | null
    in?: number[] | ListFloatFieldRefInput<$PrismaModel> | null
    notIn?: number[] | ListFloatFieldRefInput<$PrismaModel> | null
    lt?: number | FloatFieldRefInput<$PrismaModel>
    lte?: number | FloatFieldRefInput<$PrismaModel>
    gt?: number | FloatFieldRefInput<$PrismaModel>
    gte?: number | FloatFieldRefInput<$PrismaModel>
    not?: NestedFloatNullableWithAggregatesFilter<$PrismaModel> | number | null
    _count?: NestedIntNullableFilter<$PrismaModel>
    _avg?: NestedFloatNullableFilter<$PrismaModel>
    _sum?: NestedFloatNullableFilter<$PrismaModel>
    _min?: NestedFloatNullableFilter<$PrismaModel>
    _max?: NestedFloatNullableFilter<$PrismaModel>
  }

  export type NestedEnumTipoParticipacaoWithAggregatesFilter<$PrismaModel = never> = {
    equals?: $Enums.TipoParticipacao | EnumTipoParticipacaoFieldRefInput<$PrismaModel>
    in?: $Enums.TipoParticipacao[] | ListEnumTipoParticipacaoFieldRefInput<$PrismaModel>
    notIn?: $Enums.TipoParticipacao[] | ListEnumTipoParticipacaoFieldRefInput<$PrismaModel>
    not?: NestedEnumTipoParticipacaoWithAggregatesFilter<$PrismaModel> | $Enums.TipoParticipacao
    _count?: NestedIntFilter<$PrismaModel>
    _min?: NestedEnumTipoParticipacaoFilter<$PrismaModel>
    _max?: NestedEnumTipoParticipacaoFilter<$PrismaModel>
  }

  export type NestedBoolNullableWithAggregatesFilter<$PrismaModel = never> = {
    equals?: boolean | BooleanFieldRefInput<$PrismaModel> | null
    not?: NestedBoolNullableWithAggregatesFilter<$PrismaModel> | boolean | null
    _count?: NestedIntNullableFilter<$PrismaModel>
    _min?: NestedBoolNullableFilter<$PrismaModel>
    _max?: NestedBoolNullableFilter<$PrismaModel>
  }

  export type InstituicaoEspiritaCreateWithoutAtualizadoPorInput = {
    nome: string
    nome_CNPJ?: string | null
    estado?: string | null
    cidade?: string | null
    bairro?: string | null
    logradouro?: string | null
    numero?: string | null
    complemento?: string | null
    telefone?: string | null
    email?: string | null
    createdAt?: Date | string
    updatedAt?: Date | string
    sigla: string
    CEU?: string | null
    dia?: string | null
    horario?: string | null
    CNPJ: string
    criadoPor?: UsersCreateNestedOneWithoutInstituicoesCriadasInput
    Participante2025?: Participante2025CreateNestedManyWithoutInstituicaoInput
    Users?: UsersCreateNestedManyWithoutInstituicoesInput
  }

  export type InstituicaoEspiritaUncheckedCreateWithoutAtualizadoPorInput = {
    id?: number
    nome: string
    nome_CNPJ?: string | null
    estado?: string | null
    cidade?: string | null
    bairro?: string | null
    logradouro?: string | null
    numero?: string | null
    complemento?: string | null
    telefone?: string | null
    email?: string | null
    createdAt?: Date | string
    updatedAt?: Date | string
    criadoPorId?: number | null
    sigla: string
    CEU?: string | null
    dia?: string | null
    horario?: string | null
    CNPJ: string
    Participante2025?: Participante2025UncheckedCreateNestedManyWithoutInstituicaoInput
    Users?: UsersUncheckedCreateNestedManyWithoutInstituicoesInput
  }

  export type InstituicaoEspiritaCreateOrConnectWithoutAtualizadoPorInput = {
    where: InstituicaoEspiritaWhereUniqueInput
    create: XOR<InstituicaoEspiritaCreateWithoutAtualizadoPorInput, InstituicaoEspiritaUncheckedCreateWithoutAtualizadoPorInput>
  }

  export type InstituicaoEspiritaCreateManyAtualizadoPorInputEnvelope = {
    data: InstituicaoEspiritaCreateManyAtualizadoPorInput | InstituicaoEspiritaCreateManyAtualizadoPorInput[]
    skipDuplicates?: boolean
  }

  export type InstituicaoEspiritaCreateWithoutCriadoPorInput = {
    nome: string
    nome_CNPJ?: string | null
    estado?: string | null
    cidade?: string | null
    bairro?: string | null
    logradouro?: string | null
    numero?: string | null
    complemento?: string | null
    telefone?: string | null
    email?: string | null
    createdAt?: Date | string
    updatedAt?: Date | string
    sigla: string
    CEU?: string | null
    dia?: string | null
    horario?: string | null
    CNPJ: string
    atualizadoPor?: UsersCreateNestedOneWithoutInstituicoesAtualizadasInput
    Participante2025?: Participante2025CreateNestedManyWithoutInstituicaoInput
    Users?: UsersCreateNestedManyWithoutInstituicoesInput
  }

  export type InstituicaoEspiritaUncheckedCreateWithoutCriadoPorInput = {
    id?: number
    nome: string
    nome_CNPJ?: string | null
    estado?: string | null
    cidade?: string | null
    bairro?: string | null
    logradouro?: string | null
    numero?: string | null
    complemento?: string | null
    telefone?: string | null
    email?: string | null
    createdAt?: Date | string
    updatedAt?: Date | string
    sigla: string
    CEU?: string | null
    dia?: string | null
    horario?: string | null
    atualizadoPorId?: number | null
    CNPJ: string
    Participante2025?: Participante2025UncheckedCreateNestedManyWithoutInstituicaoInput
    Users?: UsersUncheckedCreateNestedManyWithoutInstituicoesInput
  }

  export type InstituicaoEspiritaCreateOrConnectWithoutCriadoPorInput = {
    where: InstituicaoEspiritaWhereUniqueInput
    create: XOR<InstituicaoEspiritaCreateWithoutCriadoPorInput, InstituicaoEspiritaUncheckedCreateWithoutCriadoPorInput>
  }

  export type InstituicaoEspiritaCreateManyCriadoPorInputEnvelope = {
    data: InstituicaoEspiritaCreateManyCriadoPorInput | InstituicaoEspiritaCreateManyCriadoPorInput[]
    skipDuplicates?: boolean
  }

  export type Participante2025CreateWithoutUserInput = {
    id?: string
    nomeCompleto: string
    nomeCracha?: string | null
    cpf?: string | null
    nomeSocial?: string | null
    dataNascimento: Date | string
    sexo: string
    email: string
    telefone: string
    nomeCompletoResponsavel?: string | null
    documentoResponsavel?: string | null
    telefoneResponsavel?: string | null
    linkPagamento?: string | null
    idade?: number | null
    valor?: number | null
    statusPagamento?: string | null
    tipoParticipacao: $Enums.TipoParticipacao
    comissao?: string | null
    tamanhoCamisa?: string | null
    cep: string
    estado?: string | null
    cidade?: string | null
    bairro?: string | null
    logradouro?: string | null
    numero?: string | null
    complemento?: string | null
    outroGenero?: string | null
    medicacao?: string | null
    alergia?: string | null
    outrasInformacoes?: string | null
    createdAt?: Date | string
    updatedAt?: Date | string
    IE: string
    vegetariano?: string
    camisa?: boolean | null
    primeiraComejaca?: boolean | null
    deficienciaAuditiva?: boolean | null
    deficienciaAutismo?: boolean | null
    deficienciaIntelectual?: boolean | null
    deficienciaParalisiaCerebral?: boolean | null
    deficienciaVisual?: boolean | null
    deficienciaFisica?: boolean | null
    deficienciaOutra?: boolean | null
    deficienciaOutraDescricao?: string | null
    otherInstitution?: string | null
    instituicao?: InstituicaoEspiritaCreateNestedOneWithoutParticipante2025Input
  }

  export type Participante2025UncheckedCreateWithoutUserInput = {
    id?: string
    nomeCompleto: string
    nomeCracha?: string | null
    cpf?: string | null
    nomeSocial?: string | null
    dataNascimento: Date | string
    sexo: string
    email: string
    telefone: string
    nomeCompletoResponsavel?: string | null
    documentoResponsavel?: string | null
    telefoneResponsavel?: string | null
    linkPagamento?: string | null
    idade?: number | null
    valor?: number | null
    statusPagamento?: string | null
    tipoParticipacao: $Enums.TipoParticipacao
    comissao?: string | null
    tamanhoCamisa?: string | null
    cep: string
    estado?: string | null
    cidade?: string | null
    bairro?: string | null
    logradouro?: string | null
    numero?: string | null
    complemento?: string | null
    outroGenero?: string | null
    medicacao?: string | null
    alergia?: string | null
    outrasInformacoes?: string | null
    createdAt?: Date | string
    updatedAt?: Date | string
    IE: string
    instituicaoId?: number | null
    vegetariano?: string
    camisa?: boolean | null
    primeiraComejaca?: boolean | null
    deficienciaAuditiva?: boolean | null
    deficienciaAutismo?: boolean | null
    deficienciaIntelectual?: boolean | null
    deficienciaParalisiaCerebral?: boolean | null
    deficienciaVisual?: boolean | null
    deficienciaFisica?: boolean | null
    deficienciaOutra?: boolean | null
    deficienciaOutraDescricao?: string | null
    otherInstitution?: string | null
  }

  export type Participante2025CreateOrConnectWithoutUserInput = {
    where: Participante2025WhereUniqueInput
    create: XOR<Participante2025CreateWithoutUserInput, Participante2025UncheckedCreateWithoutUserInput>
  }

  export type Participante2025CreateManyUserInputEnvelope = {
    data: Participante2025CreateManyUserInput | Participante2025CreateManyUserInput[]
    skipDuplicates?: boolean
  }

  export type InstituicaoEspiritaCreateWithoutUsersInput = {
    nome: string
    nome_CNPJ?: string | null
    estado?: string | null
    cidade?: string | null
    bairro?: string | null
    logradouro?: string | null
    numero?: string | null
    complemento?: string | null
    telefone?: string | null
    email?: string | null
    createdAt?: Date | string
    updatedAt?: Date | string
    sigla: string
    CEU?: string | null
    dia?: string | null
    horario?: string | null
    CNPJ: string
    atualizadoPor?: UsersCreateNestedOneWithoutInstituicoesAtualizadasInput
    criadoPor?: UsersCreateNestedOneWithoutInstituicoesCriadasInput
    Participante2025?: Participante2025CreateNestedManyWithoutInstituicaoInput
  }

  export type InstituicaoEspiritaUncheckedCreateWithoutUsersInput = {
    id?: number
    nome: string
    nome_CNPJ?: string | null
    estado?: string | null
    cidade?: string | null
    bairro?: string | null
    logradouro?: string | null
    numero?: string | null
    complemento?: string | null
    telefone?: string | null
    email?: string | null
    createdAt?: Date | string
    updatedAt?: Date | string
    criadoPorId?: number | null
    sigla: string
    CEU?: string | null
    dia?: string | null
    horario?: string | null
    atualizadoPorId?: number | null
    CNPJ: string
    Participante2025?: Participante2025UncheckedCreateNestedManyWithoutInstituicaoInput
  }

  export type InstituicaoEspiritaCreateOrConnectWithoutUsersInput = {
    where: InstituicaoEspiritaWhereUniqueInput
    create: XOR<InstituicaoEspiritaCreateWithoutUsersInput, InstituicaoEspiritaUncheckedCreateWithoutUsersInput>
  }

  export type PasswordResetTokenCreateWithoutUserInput = {
    token: string
    expiresAt: Date | string
    createdAt?: Date | string
  }

  export type PasswordResetTokenUncheckedCreateWithoutUserInput = {
    id?: number
    token: string
    expiresAt: Date | string
    createdAt?: Date | string
  }

  export type PasswordResetTokenCreateOrConnectWithoutUserInput = {
    where: PasswordResetTokenWhereUniqueInput
    create: XOR<PasswordResetTokenCreateWithoutUserInput, PasswordResetTokenUncheckedCreateWithoutUserInput>
  }

  export type PasswordResetTokenCreateManyUserInputEnvelope = {
    data: PasswordResetTokenCreateManyUserInput | PasswordResetTokenCreateManyUserInput[]
    skipDuplicates?: boolean
  }

  export type InstituicaoEspiritaUpsertWithWhereUniqueWithoutAtualizadoPorInput = {
    where: InstituicaoEspiritaWhereUniqueInput
    update: XOR<InstituicaoEspiritaUpdateWithoutAtualizadoPorInput, InstituicaoEspiritaUncheckedUpdateWithoutAtualizadoPorInput>
    create: XOR<InstituicaoEspiritaCreateWithoutAtualizadoPorInput, InstituicaoEspiritaUncheckedCreateWithoutAtualizadoPorInput>
  }

  export type InstituicaoEspiritaUpdateWithWhereUniqueWithoutAtualizadoPorInput = {
    where: InstituicaoEspiritaWhereUniqueInput
    data: XOR<InstituicaoEspiritaUpdateWithoutAtualizadoPorInput, InstituicaoEspiritaUncheckedUpdateWithoutAtualizadoPorInput>
  }

  export type InstituicaoEspiritaUpdateManyWithWhereWithoutAtualizadoPorInput = {
    where: InstituicaoEspiritaScalarWhereInput
    data: XOR<InstituicaoEspiritaUpdateManyMutationInput, InstituicaoEspiritaUncheckedUpdateManyWithoutAtualizadoPorInput>
  }

  export type InstituicaoEspiritaScalarWhereInput = {
    AND?: InstituicaoEspiritaScalarWhereInput | InstituicaoEspiritaScalarWhereInput[]
    OR?: InstituicaoEspiritaScalarWhereInput[]
    NOT?: InstituicaoEspiritaScalarWhereInput | InstituicaoEspiritaScalarWhereInput[]
    id?: IntFilter<"InstituicaoEspirita"> | number
    nome?: StringFilter<"InstituicaoEspirita"> | string
    nome_CNPJ?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    estado?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    cidade?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    bairro?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    logradouro?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    numero?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    complemento?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    telefone?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    email?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    createdAt?: DateTimeFilter<"InstituicaoEspirita"> | Date | string
    updatedAt?: DateTimeFilter<"InstituicaoEspirita"> | Date | string
    criadoPorId?: IntNullableFilter<"InstituicaoEspirita"> | number | null
    sigla?: StringFilter<"InstituicaoEspirita"> | string
    CEU?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    dia?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    horario?: StringNullableFilter<"InstituicaoEspirita"> | string | null
    atualizadoPorId?: IntNullableFilter<"InstituicaoEspirita"> | number | null
    CNPJ?: StringFilter<"InstituicaoEspirita"> | string
  }

  export type InstituicaoEspiritaUpsertWithWhereUniqueWithoutCriadoPorInput = {
    where: InstituicaoEspiritaWhereUniqueInput
    update: XOR<InstituicaoEspiritaUpdateWithoutCriadoPorInput, InstituicaoEspiritaUncheckedUpdateWithoutCriadoPorInput>
    create: XOR<InstituicaoEspiritaCreateWithoutCriadoPorInput, InstituicaoEspiritaUncheckedCreateWithoutCriadoPorInput>
  }

  export type InstituicaoEspiritaUpdateWithWhereUniqueWithoutCriadoPorInput = {
    where: InstituicaoEspiritaWhereUniqueInput
    data: XOR<InstituicaoEspiritaUpdateWithoutCriadoPorInput, InstituicaoEspiritaUncheckedUpdateWithoutCriadoPorInput>
  }

  export type InstituicaoEspiritaUpdateManyWithWhereWithoutCriadoPorInput = {
    where: InstituicaoEspiritaScalarWhereInput
    data: XOR<InstituicaoEspiritaUpdateManyMutationInput, InstituicaoEspiritaUncheckedUpdateManyWithoutCriadoPorInput>
  }

  export type Participante2025UpsertWithWhereUniqueWithoutUserInput = {
    where: Participante2025WhereUniqueInput
    update: XOR<Participante2025UpdateWithoutUserInput, Participante2025UncheckedUpdateWithoutUserInput>
    create: XOR<Participante2025CreateWithoutUserInput, Participante2025UncheckedCreateWithoutUserInput>
  }

  export type Participante2025UpdateWithWhereUniqueWithoutUserInput = {
    where: Participante2025WhereUniqueInput
    data: XOR<Participante2025UpdateWithoutUserInput, Participante2025UncheckedUpdateWithoutUserInput>
  }

  export type Participante2025UpdateManyWithWhereWithoutUserInput = {
    where: Participante2025ScalarWhereInput
    data: XOR<Participante2025UpdateManyMutationInput, Participante2025UncheckedUpdateManyWithoutUserInput>
  }

  export type Participante2025ScalarWhereInput = {
    AND?: Participante2025ScalarWhereInput | Participante2025ScalarWhereInput[]
    OR?: Participante2025ScalarWhereInput[]
    NOT?: Participante2025ScalarWhereInput | Participante2025ScalarWhereInput[]
    id?: StringFilter<"Participante2025"> | string
    nomeCompleto?: StringFilter<"Participante2025"> | string
    nomeCracha?: StringNullableFilter<"Participante2025"> | string | null
    cpf?: StringNullableFilter<"Participante2025"> | string | null
    nomeSocial?: StringNullableFilter<"Participante2025"> | string | null
    dataNascimento?: DateTimeFilter<"Participante2025"> | Date | string
    sexo?: StringFilter<"Participante2025"> | string
    email?: StringFilter<"Participante2025"> | string
    telefone?: StringFilter<"Participante2025"> | string
    nomeCompletoResponsavel?: StringNullableFilter<"Participante2025"> | string | null
    documentoResponsavel?: StringNullableFilter<"Participante2025"> | string | null
    telefoneResponsavel?: StringNullableFilter<"Participante2025"> | string | null
    linkPagamento?: StringNullableFilter<"Participante2025"> | string | null
    idade?: IntNullableFilter<"Participante2025"> | number | null
    valor?: FloatNullableFilter<"Participante2025"> | number | null
    statusPagamento?: StringNullableFilter<"Participante2025"> | string | null
    tipoParticipacao?: EnumTipoParticipacaoFilter<"Participante2025"> | $Enums.TipoParticipacao
    comissao?: StringNullableFilter<"Participante2025"> | string | null
    tamanhoCamisa?: StringNullableFilter<"Participante2025"> | string | null
    cep?: StringFilter<"Participante2025"> | string
    estado?: StringNullableFilter<"Participante2025"> | string | null
    cidade?: StringNullableFilter<"Participante2025"> | string | null
    bairro?: StringNullableFilter<"Participante2025"> | string | null
    logradouro?: StringNullableFilter<"Participante2025"> | string | null
    numero?: StringNullableFilter<"Participante2025"> | string | null
    complemento?: StringNullableFilter<"Participante2025"> | string | null
    outroGenero?: StringNullableFilter<"Participante2025"> | string | null
    medicacao?: StringNullableFilter<"Participante2025"> | string | null
    alergia?: StringNullableFilter<"Participante2025"> | string | null
    outrasInformacoes?: StringNullableFilter<"Participante2025"> | string | null
    userId?: IntNullableFilter<"Participante2025"> | number | null
    createdAt?: DateTimeFilter<"Participante2025"> | Date | string
    updatedAt?: DateTimeFilter<"Participante2025"> | Date | string
    IE?: StringFilter<"Participante2025"> | string
    instituicaoId?: IntNullableFilter<"Participante2025"> | number | null
    vegetariano?: StringFilter<"Participante2025"> | string
    camisa?: BoolNullableFilter<"Participante2025"> | boolean | null
    primeiraComejaca?: BoolNullableFilter<"Participante2025"> | boolean | null
    deficienciaAuditiva?: BoolNullableFilter<"Participante2025"> | boolean | null
    deficienciaAutismo?: BoolNullableFilter<"Participante2025"> | boolean | null
    deficienciaIntelectual?: BoolNullableFilter<"Participante2025"> | boolean | null
    deficienciaParalisiaCerebral?: BoolNullableFilter<"Participante2025"> | boolean | null
    deficienciaVisual?: BoolNullableFilter<"Participante2025"> | boolean | null
    deficienciaFisica?: BoolNullableFilter<"Participante2025"> | boolean | null
    deficienciaOutra?: BoolNullableFilter<"Participante2025"> | boolean | null
    deficienciaOutraDescricao?: StringNullableFilter<"Participante2025"> | string | null
    otherInstitution?: StringNullableFilter<"Participante2025"> | string | null
  }

  export type InstituicaoEspiritaUpsertWithWhereUniqueWithoutUsersInput = {
    where: InstituicaoEspiritaWhereUniqueInput
    update: XOR<InstituicaoEspiritaUpdateWithoutUsersInput, InstituicaoEspiritaUncheckedUpdateWithoutUsersInput>
    create: XOR<InstituicaoEspiritaCreateWithoutUsersInput, InstituicaoEspiritaUncheckedCreateWithoutUsersInput>
  }

  export type InstituicaoEspiritaUpdateWithWhereUniqueWithoutUsersInput = {
    where: InstituicaoEspiritaWhereUniqueInput
    data: XOR<InstituicaoEspiritaUpdateWithoutUsersInput, InstituicaoEspiritaUncheckedUpdateWithoutUsersInput>
  }

  export type InstituicaoEspiritaUpdateManyWithWhereWithoutUsersInput = {
    where: InstituicaoEspiritaScalarWhereInput
    data: XOR<InstituicaoEspiritaUpdateManyMutationInput, InstituicaoEspiritaUncheckedUpdateManyWithoutUsersInput>
  }

  export type PasswordResetTokenUpsertWithWhereUniqueWithoutUserInput = {
    where: PasswordResetTokenWhereUniqueInput
    update: XOR<PasswordResetTokenUpdateWithoutUserInput, PasswordResetTokenUncheckedUpdateWithoutUserInput>
    create: XOR<PasswordResetTokenCreateWithoutUserInput, PasswordResetTokenUncheckedCreateWithoutUserInput>
  }

  export type PasswordResetTokenUpdateWithWhereUniqueWithoutUserInput = {
    where: PasswordResetTokenWhereUniqueInput
    data: XOR<PasswordResetTokenUpdateWithoutUserInput, PasswordResetTokenUncheckedUpdateWithoutUserInput>
  }

  export type PasswordResetTokenUpdateManyWithWhereWithoutUserInput = {
    where: PasswordResetTokenScalarWhereInput
    data: XOR<PasswordResetTokenUpdateManyMutationInput, PasswordResetTokenUncheckedUpdateManyWithoutUserInput>
  }

  export type PasswordResetTokenScalarWhereInput = {
    AND?: PasswordResetTokenScalarWhereInput | PasswordResetTokenScalarWhereInput[]
    OR?: PasswordResetTokenScalarWhereInput[]
    NOT?: PasswordResetTokenScalarWhereInput | PasswordResetTokenScalarWhereInput[]
    id?: IntFilter<"PasswordResetToken"> | number
    token?: StringFilter<"PasswordResetToken"> | string
    userId?: IntFilter<"PasswordResetToken"> | number
    expiresAt?: DateTimeFilter<"PasswordResetToken"> | Date | string
    createdAt?: DateTimeFilter<"PasswordResetToken"> | Date | string
  }

  export type UsersCreateWithoutInstituicoesAtualizadasInput = {
    name: string
    email: string
    password: string
    isVerified?: boolean
    createdAt?: Date | string
    updatedAt?: Date | string
    verificationCode?: string | null
    verificationCodeExpiration?: Date | string | null
    lastVerificationRequest?: Date | string
    role?: $Enums.Role
    comunicacaocomejaca?: string | null
    comunicacaomovimento?: string | null
    telefone?: string | null
    resetTokenVersion?: number
    instituicoesCriadas?: InstituicaoEspiritaCreateNestedManyWithoutCriadoPorInput
    Participante2025?: Participante2025CreateNestedManyWithoutUserInput
    instituicoes?: InstituicaoEspiritaCreateNestedManyWithoutUsersInput
    passwordResetTokens?: PasswordResetTokenCreateNestedManyWithoutUserInput
  }

  export type UsersUncheckedCreateWithoutInstituicoesAtualizadasInput = {
    id?: number
    name: string
    email: string
    password: string
    isVerified?: boolean
    createdAt?: Date | string
    updatedAt?: Date | string
    verificationCode?: string | null
    verificationCodeExpiration?: Date | string | null
    lastVerificationRequest?: Date | string
    role?: $Enums.Role
    comunicacaocomejaca?: string | null
    comunicacaomovimento?: string | null
    telefone?: string | null
    resetTokenVersion?: number
    instituicoesCriadas?: InstituicaoEspiritaUncheckedCreateNestedManyWithoutCriadoPorInput
    Participante2025?: Participante2025UncheckedCreateNestedManyWithoutUserInput
    instituicoes?: InstituicaoEspiritaUncheckedCreateNestedManyWithoutUsersInput
    passwordResetTokens?: PasswordResetTokenUncheckedCreateNestedManyWithoutUserInput
  }

  export type UsersCreateOrConnectWithoutInstituicoesAtualizadasInput = {
    where: UsersWhereUniqueInput
    create: XOR<UsersCreateWithoutInstituicoesAtualizadasInput, UsersUncheckedCreateWithoutInstituicoesAtualizadasInput>
  }

  export type UsersCreateWithoutInstituicoesCriadasInput = {
    name: string
    email: string
    password: string
    isVerified?: boolean
    createdAt?: Date | string
    updatedAt?: Date | string
    verificationCode?: string | null
    verificationCodeExpiration?: Date | string | null
    lastVerificationRequest?: Date | string
    role?: $Enums.Role
    comunicacaocomejaca?: string | null
    comunicacaomovimento?: string | null
    telefone?: string | null
    resetTokenVersion?: number
    instituicoesAtualizadas?: InstituicaoEspiritaCreateNestedManyWithoutAtualizadoPorInput
    Participante2025?: Participante2025CreateNestedManyWithoutUserInput
    instituicoes?: InstituicaoEspiritaCreateNestedManyWithoutUsersInput
    passwordResetTokens?: PasswordResetTokenCreateNestedManyWithoutUserInput
  }

  export type UsersUncheckedCreateWithoutInstituicoesCriadasInput = {
    id?: number
    name: string
    email: string
    password: string
    isVerified?: boolean
    createdAt?: Date | string
    updatedAt?: Date | string
    verificationCode?: string | null
    verificationCodeExpiration?: Date | string | null
    lastVerificationRequest?: Date | string
    role?: $Enums.Role
    comunicacaocomejaca?: string | null
    comunicacaomovimento?: string | null
    telefone?: string | null
    resetTokenVersion?: number
    instituicoesAtualizadas?: InstituicaoEspiritaUncheckedCreateNestedManyWithoutAtualizadoPorInput
    Participante2025?: Participante2025UncheckedCreateNestedManyWithoutUserInput
    instituicoes?: InstituicaoEspiritaUncheckedCreateNestedManyWithoutUsersInput
    passwordResetTokens?: PasswordResetTokenUncheckedCreateNestedManyWithoutUserInput
  }

  export type UsersCreateOrConnectWithoutInstituicoesCriadasInput = {
    where: UsersWhereUniqueInput
    create: XOR<UsersCreateWithoutInstituicoesCriadasInput, UsersUncheckedCreateWithoutInstituicoesCriadasInput>
  }

  export type Participante2025CreateWithoutInstituicaoInput = {
    id?: string
    nomeCompleto: string
    nomeCracha?: string | null
    cpf?: string | null
    nomeSocial?: string | null
    dataNascimento: Date | string
    sexo: string
    email: string
    telefone: string
    nomeCompletoResponsavel?: string | null
    documentoResponsavel?: string | null
    telefoneResponsavel?: string | null
    linkPagamento?: string | null
    idade?: number | null
    valor?: number | null
    statusPagamento?: string | null
    tipoParticipacao: $Enums.TipoParticipacao
    comissao?: string | null
    tamanhoCamisa?: string | null
    cep: string
    estado?: string | null
    cidade?: string | null
    bairro?: string | null
    logradouro?: string | null
    numero?: string | null
    complemento?: string | null
    outroGenero?: string | null
    medicacao?: string | null
    alergia?: string | null
    outrasInformacoes?: string | null
    createdAt?: Date | string
    updatedAt?: Date | string
    IE: string
    vegetariano?: string
    camisa?: boolean | null
    primeiraComejaca?: boolean | null
    deficienciaAuditiva?: boolean | null
    deficienciaAutismo?: boolean | null
    deficienciaIntelectual?: boolean | null
    deficienciaParalisiaCerebral?: boolean | null
    deficienciaVisual?: boolean | null
    deficienciaFisica?: boolean | null
    deficienciaOutra?: boolean | null
    deficienciaOutraDescricao?: string | null
    otherInstitution?: string | null
    user?: UsersCreateNestedOneWithoutParticipante2025Input
  }

  export type Participante2025UncheckedCreateWithoutInstituicaoInput = {
    id?: string
    nomeCompleto: string
    nomeCracha?: string | null
    cpf?: string | null
    nomeSocial?: string | null
    dataNascimento: Date | string
    sexo: string
    email: string
    telefone: string
    nomeCompletoResponsavel?: string | null
    documentoResponsavel?: string | null
    telefoneResponsavel?: string | null
    linkPagamento?: string | null
    idade?: number | null
    valor?: number | null
    statusPagamento?: string | null
    tipoParticipacao: $Enums.TipoParticipacao
    comissao?: string | null
    tamanhoCamisa?: string | null
    cep: string
    estado?: string | null
    cidade?: string | null
    bairro?: string | null
    logradouro?: string | null
    numero?: string | null
    complemento?: string | null
    outroGenero?: string | null
    medicacao?: string | null
    alergia?: string | null
    outrasInformacoes?: string | null
    userId?: number | null
    createdAt?: Date | string
    updatedAt?: Date | string
    IE: string
    vegetariano?: string
    camisa?: boolean | null
    primeiraComejaca?: boolean | null
    deficienciaAuditiva?: boolean | null
    deficienciaAutismo?: boolean | null
    deficienciaIntelectual?: boolean | null
    deficienciaParalisiaCerebral?: boolean | null
    deficienciaVisual?: boolean | null
    deficienciaFisica?: boolean | null
    deficienciaOutra?: boolean | null
    deficienciaOutraDescricao?: string | null
    otherInstitution?: string | null
  }

  export type Participante2025CreateOrConnectWithoutInstituicaoInput = {
    where: Participante2025WhereUniqueInput
    create: XOR<Participante2025CreateWithoutInstituicaoInput, Participante2025UncheckedCreateWithoutInstituicaoInput>
  }

  export type Participante2025CreateManyInstituicaoInputEnvelope = {
    data: Participante2025CreateManyInstituicaoInput | Participante2025CreateManyInstituicaoInput[]
    skipDuplicates?: boolean
  }

  export type UsersCreateWithoutInstituicoesInput = {
    name: string
    email: string
    password: string
    isVerified?: boolean
    createdAt?: Date | string
    updatedAt?: Date | string
    verificationCode?: string | null
    verificationCodeExpiration?: Date | string | null
    lastVerificationRequest?: Date | string
    role?: $Enums.Role
    comunicacaocomejaca?: string | null
    comunicacaomovimento?: string | null
    telefone?: string | null
    resetTokenVersion?: number
    instituicoesAtualizadas?: InstituicaoEspiritaCreateNestedManyWithoutAtualizadoPorInput
    instituicoesCriadas?: InstituicaoEspiritaCreateNestedManyWithoutCriadoPorInput
    Participante2025?: Participante2025CreateNestedManyWithoutUserInput
    passwordResetTokens?: PasswordResetTokenCreateNestedManyWithoutUserInput
  }

  export type UsersUncheckedCreateWithoutInstituicoesInput = {
    id?: number
    name: string
    email: string
    password: string
    isVerified?: boolean
    createdAt?: Date | string
    updatedAt?: Date | string
    verificationCode?: string | null
    verificationCodeExpiration?: Date | string | null
    lastVerificationRequest?: Date | string
    role?: $Enums.Role
    comunicacaocomejaca?: string | null
    comunicacaomovimento?: string | null
    telefone?: string | null
    resetTokenVersion?: number
    instituicoesAtualizadas?: InstituicaoEspiritaUncheckedCreateNestedManyWithoutAtualizadoPorInput
    instituicoesCriadas?: InstituicaoEspiritaUncheckedCreateNestedManyWithoutCriadoPorInput
    Participante2025?: Participante2025UncheckedCreateNestedManyWithoutUserInput
    passwordResetTokens?: PasswordResetTokenUncheckedCreateNestedManyWithoutUserInput
  }

  export type UsersCreateOrConnectWithoutInstituicoesInput = {
    where: UsersWhereUniqueInput
    create: XOR<UsersCreateWithoutInstituicoesInput, UsersUncheckedCreateWithoutInstituicoesInput>
  }

  export type UsersUpsertWithoutInstituicoesAtualizadasInput = {
    update: XOR<UsersUpdateWithoutInstituicoesAtualizadasInput, UsersUncheckedUpdateWithoutInstituicoesAtualizadasInput>
    create: XOR<UsersCreateWithoutInstituicoesAtualizadasInput, UsersUncheckedCreateWithoutInstituicoesAtualizadasInput>
    where?: UsersWhereInput
  }

  export type UsersUpdateToOneWithWhereWithoutInstituicoesAtualizadasInput = {
    where?: UsersWhereInput
    data: XOR<UsersUpdateWithoutInstituicoesAtualizadasInput, UsersUncheckedUpdateWithoutInstituicoesAtualizadasInput>
  }

  export type UsersUpdateWithoutInstituicoesAtualizadasInput = {
    name?: StringFieldUpdateOperationsInput | string
    email?: StringFieldUpdateOperationsInput | string
    password?: StringFieldUpdateOperationsInput | string
    isVerified?: BoolFieldUpdateOperationsInput | boolean
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    verificationCode?: NullableStringFieldUpdateOperationsInput | string | null
    verificationCodeExpiration?: NullableDateTimeFieldUpdateOperationsInput | Date | string | null
    lastVerificationRequest?: DateTimeFieldUpdateOperationsInput | Date | string
    role?: EnumRoleFieldUpdateOperationsInput | $Enums.Role
    comunicacaocomejaca?: NullableStringFieldUpdateOperationsInput | string | null
    comunicacaomovimento?: NullableStringFieldUpdateOperationsInput | string | null
    telefone?: NullableStringFieldUpdateOperationsInput | string | null
    resetTokenVersion?: IntFieldUpdateOperationsInput | number
    instituicoesCriadas?: InstituicaoEspiritaUpdateManyWithoutCriadoPorNestedInput
    Participante2025?: Participante2025UpdateManyWithoutUserNestedInput
    instituicoes?: InstituicaoEspiritaUpdateManyWithoutUsersNestedInput
    passwordResetTokens?: PasswordResetTokenUpdateManyWithoutUserNestedInput
  }

  export type UsersUncheckedUpdateWithoutInstituicoesAtualizadasInput = {
    id?: IntFieldUpdateOperationsInput | number
    name?: StringFieldUpdateOperationsInput | string
    email?: StringFieldUpdateOperationsInput | string
    password?: StringFieldUpdateOperationsInput | string
    isVerified?: BoolFieldUpdateOperationsInput | boolean
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    verificationCode?: NullableStringFieldUpdateOperationsInput | string | null
    verificationCodeExpiration?: NullableDateTimeFieldUpdateOperationsInput | Date | string | null
    lastVerificationRequest?: DateTimeFieldUpdateOperationsInput | Date | string
    role?: EnumRoleFieldUpdateOperationsInput | $Enums.Role
    comunicacaocomejaca?: NullableStringFieldUpdateOperationsInput | string | null
    comunicacaomovimento?: NullableStringFieldUpdateOperationsInput | string | null
    telefone?: NullableStringFieldUpdateOperationsInput | string | null
    resetTokenVersion?: IntFieldUpdateOperationsInput | number
    instituicoesCriadas?: InstituicaoEspiritaUncheckedUpdateManyWithoutCriadoPorNestedInput
    Participante2025?: Participante2025UncheckedUpdateManyWithoutUserNestedInput
    instituicoes?: InstituicaoEspiritaUncheckedUpdateManyWithoutUsersNestedInput
    passwordResetTokens?: PasswordResetTokenUncheckedUpdateManyWithoutUserNestedInput
  }

  export type UsersUpsertWithoutInstituicoesCriadasInput = {
    update: XOR<UsersUpdateWithoutInstituicoesCriadasInput, UsersUncheckedUpdateWithoutInstituicoesCriadasInput>
    create: XOR<UsersCreateWithoutInstituicoesCriadasInput, UsersUncheckedCreateWithoutInstituicoesCriadasInput>
    where?: UsersWhereInput
  }

  export type UsersUpdateToOneWithWhereWithoutInstituicoesCriadasInput = {
    where?: UsersWhereInput
    data: XOR<UsersUpdateWithoutInstituicoesCriadasInput, UsersUncheckedUpdateWithoutInstituicoesCriadasInput>
  }

  export type UsersUpdateWithoutInstituicoesCriadasInput = {
    name?: StringFieldUpdateOperationsInput | string
    email?: StringFieldUpdateOperationsInput | string
    password?: StringFieldUpdateOperationsInput | string
    isVerified?: BoolFieldUpdateOperationsInput | boolean
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    verificationCode?: NullableStringFieldUpdateOperationsInput | string | null
    verificationCodeExpiration?: NullableDateTimeFieldUpdateOperationsInput | Date | string | null
    lastVerificationRequest?: DateTimeFieldUpdateOperationsInput | Date | string
    role?: EnumRoleFieldUpdateOperationsInput | $Enums.Role
    comunicacaocomejaca?: NullableStringFieldUpdateOperationsInput | string | null
    comunicacaomovimento?: NullableStringFieldUpdateOperationsInput | string | null
    telefone?: NullableStringFieldUpdateOperationsInput | string | null
    resetTokenVersion?: IntFieldUpdateOperationsInput | number
    instituicoesAtualizadas?: InstituicaoEspiritaUpdateManyWithoutAtualizadoPorNestedInput
    Participante2025?: Participante2025UpdateManyWithoutUserNestedInput
    instituicoes?: InstituicaoEspiritaUpdateManyWithoutUsersNestedInput
    passwordResetTokens?: PasswordResetTokenUpdateManyWithoutUserNestedInput
  }

  export type UsersUncheckedUpdateWithoutInstituicoesCriadasInput = {
    id?: IntFieldUpdateOperationsInput | number
    name?: StringFieldUpdateOperationsInput | string
    email?: StringFieldUpdateOperationsInput | string
    password?: StringFieldUpdateOperationsInput | string
    isVerified?: BoolFieldUpdateOperationsInput | boolean
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    verificationCode?: NullableStringFieldUpdateOperationsInput | string | null
    verificationCodeExpiration?: NullableDateTimeFieldUpdateOperationsInput | Date | string | null
    lastVerificationRequest?: DateTimeFieldUpdateOperationsInput | Date | string
    role?: EnumRoleFieldUpdateOperationsInput | $Enums.Role
    comunicacaocomejaca?: NullableStringFieldUpdateOperationsInput | string | null
    comunicacaomovimento?: NullableStringFieldUpdateOperationsInput | string | null
    telefone?: NullableStringFieldUpdateOperationsInput | string | null
    resetTokenVersion?: IntFieldUpdateOperationsInput | number
    instituicoesAtualizadas?: InstituicaoEspiritaUncheckedUpdateManyWithoutAtualizadoPorNestedInput
    Participante2025?: Participante2025UncheckedUpdateManyWithoutUserNestedInput
    instituicoes?: InstituicaoEspiritaUncheckedUpdateManyWithoutUsersNestedInput
    passwordResetTokens?: PasswordResetTokenUncheckedUpdateManyWithoutUserNestedInput
  }

  export type Participante2025UpsertWithWhereUniqueWithoutInstituicaoInput = {
    where: Participante2025WhereUniqueInput
    update: XOR<Participante2025UpdateWithoutInstituicaoInput, Participante2025UncheckedUpdateWithoutInstituicaoInput>
    create: XOR<Participante2025CreateWithoutInstituicaoInput, Participante2025UncheckedCreateWithoutInstituicaoInput>
  }

  export type Participante2025UpdateWithWhereUniqueWithoutInstituicaoInput = {
    where: Participante2025WhereUniqueInput
    data: XOR<Participante2025UpdateWithoutInstituicaoInput, Participante2025UncheckedUpdateWithoutInstituicaoInput>
  }

  export type Participante2025UpdateManyWithWhereWithoutInstituicaoInput = {
    where: Participante2025ScalarWhereInput
    data: XOR<Participante2025UpdateManyMutationInput, Participante2025UncheckedUpdateManyWithoutInstituicaoInput>
  }

  export type UsersUpsertWithWhereUniqueWithoutInstituicoesInput = {
    where: UsersWhereUniqueInput
    update: XOR<UsersUpdateWithoutInstituicoesInput, UsersUncheckedUpdateWithoutInstituicoesInput>
    create: XOR<UsersCreateWithoutInstituicoesInput, UsersUncheckedCreateWithoutInstituicoesInput>
  }

  export type UsersUpdateWithWhereUniqueWithoutInstituicoesInput = {
    where: UsersWhereUniqueInput
    data: XOR<UsersUpdateWithoutInstituicoesInput, UsersUncheckedUpdateWithoutInstituicoesInput>
  }

  export type UsersUpdateManyWithWhereWithoutInstituicoesInput = {
    where: UsersScalarWhereInput
    data: XOR<UsersUpdateManyMutationInput, UsersUncheckedUpdateManyWithoutInstituicoesInput>
  }

  export type UsersScalarWhereInput = {
    AND?: UsersScalarWhereInput | UsersScalarWhereInput[]
    OR?: UsersScalarWhereInput[]
    NOT?: UsersScalarWhereInput | UsersScalarWhereInput[]
    id?: IntFilter<"Users"> | number
    name?: StringFilter<"Users"> | string
    email?: StringFilter<"Users"> | string
    password?: StringFilter<"Users"> | string
    isVerified?: BoolFilter<"Users"> | boolean
    createdAt?: DateTimeFilter<"Users"> | Date | string
    updatedAt?: DateTimeFilter<"Users"> | Date | string
    verificationCode?: StringNullableFilter<"Users"> | string | null
    verificationCodeExpiration?: DateTimeNullableFilter<"Users"> | Date | string | null
    lastVerificationRequest?: DateTimeFilter<"Users"> | Date | string
    role?: EnumRoleFilter<"Users"> | $Enums.Role
    comunicacaocomejaca?: StringNullableFilter<"Users"> | string | null
    comunicacaomovimento?: StringNullableFilter<"Users"> | string | null
    telefone?: StringNullableFilter<"Users"> | string | null
    resetTokenVersion?: IntFilter<"Users"> | number
  }

  export type InstituicaoEspiritaCreateWithoutParticipante2025Input = {
    nome: string
    nome_CNPJ?: string | null
    estado?: string | null
    cidade?: string | null
    bairro?: string | null
    logradouro?: string | null
    numero?: string | null
    complemento?: string | null
    telefone?: string | null
    email?: string | null
    createdAt?: Date | string
    updatedAt?: Date | string
    sigla: string
    CEU?: string | null
    dia?: string | null
    horario?: string | null
    CNPJ: string
    atualizadoPor?: UsersCreateNestedOneWithoutInstituicoesAtualizadasInput
    criadoPor?: UsersCreateNestedOneWithoutInstituicoesCriadasInput
    Users?: UsersCreateNestedManyWithoutInstituicoesInput
  }

  export type InstituicaoEspiritaUncheckedCreateWithoutParticipante2025Input = {
    id?: number
    nome: string
    nome_CNPJ?: string | null
    estado?: string | null
    cidade?: string | null
    bairro?: string | null
    logradouro?: string | null
    numero?: string | null
    complemento?: string | null
    telefone?: string | null
    email?: string | null
    createdAt?: Date | string
    updatedAt?: Date | string
    criadoPorId?: number | null
    sigla: string
    CEU?: string | null
    dia?: string | null
    horario?: string | null
    atualizadoPorId?: number | null
    CNPJ: string
    Users?: UsersUncheckedCreateNestedManyWithoutInstituicoesInput
  }

  export type InstituicaoEspiritaCreateOrConnectWithoutParticipante2025Input = {
    where: InstituicaoEspiritaWhereUniqueInput
    create: XOR<InstituicaoEspiritaCreateWithoutParticipante2025Input, InstituicaoEspiritaUncheckedCreateWithoutParticipante2025Input>
  }

  export type UsersCreateWithoutParticipante2025Input = {
    name: string
    email: string
    password: string
    isVerified?: boolean
    createdAt?: Date | string
    updatedAt?: Date | string
    verificationCode?: string | null
    verificationCodeExpiration?: Date | string | null
    lastVerificationRequest?: Date | string
    role?: $Enums.Role
    comunicacaocomejaca?: string | null
    comunicacaomovimento?: string | null
    telefone?: string | null
    resetTokenVersion?: number
    instituicoesAtualizadas?: InstituicaoEspiritaCreateNestedManyWithoutAtualizadoPorInput
    instituicoesCriadas?: InstituicaoEspiritaCreateNestedManyWithoutCriadoPorInput
    instituicoes?: InstituicaoEspiritaCreateNestedManyWithoutUsersInput
    passwordResetTokens?: PasswordResetTokenCreateNestedManyWithoutUserInput
  }

  export type UsersUncheckedCreateWithoutParticipante2025Input = {
    id?: number
    name: string
    email: string
    password: string
    isVerified?: boolean
    createdAt?: Date | string
    updatedAt?: Date | string
    verificationCode?: string | null
    verificationCodeExpiration?: Date | string | null
    lastVerificationRequest?: Date | string
    role?: $Enums.Role
    comunicacaocomejaca?: string | null
    comunicacaomovimento?: string | null
    telefone?: string | null
    resetTokenVersion?: number
    instituicoesAtualizadas?: InstituicaoEspiritaUncheckedCreateNestedManyWithoutAtualizadoPorInput
    instituicoesCriadas?: InstituicaoEspiritaUncheckedCreateNestedManyWithoutCriadoPorInput
    instituicoes?: InstituicaoEspiritaUncheckedCreateNestedManyWithoutUsersInput
    passwordResetTokens?: PasswordResetTokenUncheckedCreateNestedManyWithoutUserInput
  }

  export type UsersCreateOrConnectWithoutParticipante2025Input = {
    where: UsersWhereUniqueInput
    create: XOR<UsersCreateWithoutParticipante2025Input, UsersUncheckedCreateWithoutParticipante2025Input>
  }

  export type InstituicaoEspiritaUpsertWithoutParticipante2025Input = {
    update: XOR<InstituicaoEspiritaUpdateWithoutParticipante2025Input, InstituicaoEspiritaUncheckedUpdateWithoutParticipante2025Input>
    create: XOR<InstituicaoEspiritaCreateWithoutParticipante2025Input, InstituicaoEspiritaUncheckedCreateWithoutParticipante2025Input>
    where?: InstituicaoEspiritaWhereInput
  }

  export type InstituicaoEspiritaUpdateToOneWithWhereWithoutParticipante2025Input = {
    where?: InstituicaoEspiritaWhereInput
    data: XOR<InstituicaoEspiritaUpdateWithoutParticipante2025Input, InstituicaoEspiritaUncheckedUpdateWithoutParticipante2025Input>
  }

  export type InstituicaoEspiritaUpdateWithoutParticipante2025Input = {
    nome?: StringFieldUpdateOperationsInput | string
    nome_CNPJ?: NullableStringFieldUpdateOperationsInput | string | null
    estado?: NullableStringFieldUpdateOperationsInput | string | null
    cidade?: NullableStringFieldUpdateOperationsInput | string | null
    bairro?: NullableStringFieldUpdateOperationsInput | string | null
    logradouro?: NullableStringFieldUpdateOperationsInput | string | null
    numero?: NullableStringFieldUpdateOperationsInput | string | null
    complemento?: NullableStringFieldUpdateOperationsInput | string | null
    telefone?: NullableStringFieldUpdateOperationsInput | string | null
    email?: NullableStringFieldUpdateOperationsInput | string | null
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    sigla?: StringFieldUpdateOperationsInput | string
    CEU?: NullableStringFieldUpdateOperationsInput | string | null
    dia?: NullableStringFieldUpdateOperationsInput | string | null
    horario?: NullableStringFieldUpdateOperationsInput | string | null
    CNPJ?: StringFieldUpdateOperationsInput | string
    atualizadoPor?: UsersUpdateOneWithoutInstituicoesAtualizadasNestedInput
    criadoPor?: UsersUpdateOneWithoutInstituicoesCriadasNestedInput
    Users?: UsersUpdateManyWithoutInstituicoesNestedInput
  }

  export type InstituicaoEspiritaUncheckedUpdateWithoutParticipante2025Input = {
    id?: IntFieldUpdateOperationsInput | number
    nome?: StringFieldUpdateOperationsInput | string
    nome_CNPJ?: NullableStringFieldUpdateOperationsInput | string | null
    estado?: NullableStringFieldUpdateOperationsInput | string | null
    cidade?: NullableStringFieldUpdateOperationsInput | string | null
    bairro?: NullableStringFieldUpdateOperationsInput | string | null
    logradouro?: NullableStringFieldUpdateOperationsInput | string | null
    numero?: NullableStringFieldUpdateOperationsInput | string | null
    complemento?: NullableStringFieldUpdateOperationsInput | string | null
    telefone?: NullableStringFieldUpdateOperationsInput | string | null
    email?: NullableStringFieldUpdateOperationsInput | string | null
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    criadoPorId?: NullableIntFieldUpdateOperationsInput | number | null
    sigla?: StringFieldUpdateOperationsInput | string
    CEU?: NullableStringFieldUpdateOperationsInput | string | null
    dia?: NullableStringFieldUpdateOperationsInput | string | null
    horario?: NullableStringFieldUpdateOperationsInput | string | null
    atualizadoPorId?: NullableIntFieldUpdateOperationsInput | number | null
    CNPJ?: StringFieldUpdateOperationsInput | string
    Users?: UsersUncheckedUpdateManyWithoutInstituicoesNestedInput
  }

  export type UsersUpsertWithoutParticipante2025Input = {
    update: XOR<UsersUpdateWithoutParticipante2025Input, UsersUncheckedUpdateWithoutParticipante2025Input>
    create: XOR<UsersCreateWithoutParticipante2025Input, UsersUncheckedCreateWithoutParticipante2025Input>
    where?: UsersWhereInput
  }

  export type UsersUpdateToOneWithWhereWithoutParticipante2025Input = {
    where?: UsersWhereInput
    data: XOR<UsersUpdateWithoutParticipante2025Input, UsersUncheckedUpdateWithoutParticipante2025Input>
  }

  export type UsersUpdateWithoutParticipante2025Input = {
    name?: StringFieldUpdateOperationsInput | string
    email?: StringFieldUpdateOperationsInput | string
    password?: StringFieldUpdateOperationsInput | string
    isVerified?: BoolFieldUpdateOperationsInput | boolean
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    verificationCode?: NullableStringFieldUpdateOperationsInput | string | null
    verificationCodeExpiration?: NullableDateTimeFieldUpdateOperationsInput | Date | string | null
    lastVerificationRequest?: DateTimeFieldUpdateOperationsInput | Date | string
    role?: EnumRoleFieldUpdateOperationsInput | $Enums.Role
    comunicacaocomejaca?: NullableStringFieldUpdateOperationsInput | string | null
    comunicacaomovimento?: NullableStringFieldUpdateOperationsInput | string | null
    telefone?: NullableStringFieldUpdateOperationsInput | string | null
    resetTokenVersion?: IntFieldUpdateOperationsInput | number
    instituicoesAtualizadas?: InstituicaoEspiritaUpdateManyWithoutAtualizadoPorNestedInput
    instituicoesCriadas?: InstituicaoEspiritaUpdateManyWithoutCriadoPorNestedInput
    instituicoes?: InstituicaoEspiritaUpdateManyWithoutUsersNestedInput
    passwordResetTokens?: PasswordResetTokenUpdateManyWithoutUserNestedInput
  }

  export type UsersUncheckedUpdateWithoutParticipante2025Input = {
    id?: IntFieldUpdateOperationsInput | number
    name?: StringFieldUpdateOperationsInput | string
    email?: StringFieldUpdateOperationsInput | string
    password?: StringFieldUpdateOperationsInput | string
    isVerified?: BoolFieldUpdateOperationsInput | boolean
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    verificationCode?: NullableStringFieldUpdateOperationsInput | string | null
    verificationCodeExpiration?: NullableDateTimeFieldUpdateOperationsInput | Date | string | null
    lastVerificationRequest?: DateTimeFieldUpdateOperationsInput | Date | string
    role?: EnumRoleFieldUpdateOperationsInput | $Enums.Role
    comunicacaocomejaca?: NullableStringFieldUpdateOperationsInput | string | null
    comunicacaomovimento?: NullableStringFieldUpdateOperationsInput | string | null
    telefone?: NullableStringFieldUpdateOperationsInput | string | null
    resetTokenVersion?: IntFieldUpdateOperationsInput | number
    instituicoesAtualizadas?: InstituicaoEspiritaUncheckedUpdateManyWithoutAtualizadoPorNestedInput
    instituicoesCriadas?: InstituicaoEspiritaUncheckedUpdateManyWithoutCriadoPorNestedInput
    instituicoes?: InstituicaoEspiritaUncheckedUpdateManyWithoutUsersNestedInput
    passwordResetTokens?: PasswordResetTokenUncheckedUpdateManyWithoutUserNestedInput
  }

  export type UsersCreateWithoutPasswordResetTokensInput = {
    name: string
    email: string
    password: string
    isVerified?: boolean
    createdAt?: Date | string
    updatedAt?: Date | string
    verificationCode?: string | null
    verificationCodeExpiration?: Date | string | null
    lastVerificationRequest?: Date | string
    role?: $Enums.Role
    comunicacaocomejaca?: string | null
    comunicacaomovimento?: string | null
    telefone?: string | null
    resetTokenVersion?: number
    instituicoesAtualizadas?: InstituicaoEspiritaCreateNestedManyWithoutAtualizadoPorInput
    instituicoesCriadas?: InstituicaoEspiritaCreateNestedManyWithoutCriadoPorInput
    Participante2025?: Participante2025CreateNestedManyWithoutUserInput
    instituicoes?: InstituicaoEspiritaCreateNestedManyWithoutUsersInput
  }

  export type UsersUncheckedCreateWithoutPasswordResetTokensInput = {
    id?: number
    name: string
    email: string
    password: string
    isVerified?: boolean
    createdAt?: Date | string
    updatedAt?: Date | string
    verificationCode?: string | null
    verificationCodeExpiration?: Date | string | null
    lastVerificationRequest?: Date | string
    role?: $Enums.Role
    comunicacaocomejaca?: string | null
    comunicacaomovimento?: string | null
    telefone?: string | null
    resetTokenVersion?: number
    instituicoesAtualizadas?: InstituicaoEspiritaUncheckedCreateNestedManyWithoutAtualizadoPorInput
    instituicoesCriadas?: InstituicaoEspiritaUncheckedCreateNestedManyWithoutCriadoPorInput
    Participante2025?: Participante2025UncheckedCreateNestedManyWithoutUserInput
    instituicoes?: InstituicaoEspiritaUncheckedCreateNestedManyWithoutUsersInput
  }

  export type UsersCreateOrConnectWithoutPasswordResetTokensInput = {
    where: UsersWhereUniqueInput
    create: XOR<UsersCreateWithoutPasswordResetTokensInput, UsersUncheckedCreateWithoutPasswordResetTokensInput>
  }

  export type UsersUpsertWithoutPasswordResetTokensInput = {
    update: XOR<UsersUpdateWithoutPasswordResetTokensInput, UsersUncheckedUpdateWithoutPasswordResetTokensInput>
    create: XOR<UsersCreateWithoutPasswordResetTokensInput, UsersUncheckedCreateWithoutPasswordResetTokensInput>
    where?: UsersWhereInput
  }

  export type UsersUpdateToOneWithWhereWithoutPasswordResetTokensInput = {
    where?: UsersWhereInput
    data: XOR<UsersUpdateWithoutPasswordResetTokensInput, UsersUncheckedUpdateWithoutPasswordResetTokensInput>
  }

  export type UsersUpdateWithoutPasswordResetTokensInput = {
    name?: StringFieldUpdateOperationsInput | string
    email?: StringFieldUpdateOperationsInput | string
    password?: StringFieldUpdateOperationsInput | string
    isVerified?: BoolFieldUpdateOperationsInput | boolean
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    verificationCode?: NullableStringFieldUpdateOperationsInput | string | null
    verificationCodeExpiration?: NullableDateTimeFieldUpdateOperationsInput | Date | string | null
    lastVerificationRequest?: DateTimeFieldUpdateOperationsInput | Date | string
    role?: EnumRoleFieldUpdateOperationsInput | $Enums.Role
    comunicacaocomejaca?: NullableStringFieldUpdateOperationsInput | string | null
    comunicacaomovimento?: NullableStringFieldUpdateOperationsInput | string | null
    telefone?: NullableStringFieldUpdateOperationsInput | string | null
    resetTokenVersion?: IntFieldUpdateOperationsInput | number
    instituicoesAtualizadas?: InstituicaoEspiritaUpdateManyWithoutAtualizadoPorNestedInput
    instituicoesCriadas?: InstituicaoEspiritaUpdateManyWithoutCriadoPorNestedInput
    Participante2025?: Participante2025UpdateManyWithoutUserNestedInput
    instituicoes?: InstituicaoEspiritaUpdateManyWithoutUsersNestedInput
  }

  export type UsersUncheckedUpdateWithoutPasswordResetTokensInput = {
    id?: IntFieldUpdateOperationsInput | number
    name?: StringFieldUpdateOperationsInput | string
    email?: StringFieldUpdateOperationsInput | string
    password?: StringFieldUpdateOperationsInput | string
    isVerified?: BoolFieldUpdateOperationsInput | boolean
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    verificationCode?: NullableStringFieldUpdateOperationsInput | string | null
    verificationCodeExpiration?: NullableDateTimeFieldUpdateOperationsInput | Date | string | null
    lastVerificationRequest?: DateTimeFieldUpdateOperationsInput | Date | string
    role?: EnumRoleFieldUpdateOperationsInput | $Enums.Role
    comunicacaocomejaca?: NullableStringFieldUpdateOperationsInput | string | null
    comunicacaomovimento?: NullableStringFieldUpdateOperationsInput | string | null
    telefone?: NullableStringFieldUpdateOperationsInput | string | null
    resetTokenVersion?: IntFieldUpdateOperationsInput | number
    instituicoesAtualizadas?: InstituicaoEspiritaUncheckedUpdateManyWithoutAtualizadoPorNestedInput
    instituicoesCriadas?: InstituicaoEspiritaUncheckedUpdateManyWithoutCriadoPorNestedInput
    Participante2025?: Participante2025UncheckedUpdateManyWithoutUserNestedInput
    instituicoes?: InstituicaoEspiritaUncheckedUpdateManyWithoutUsersNestedInput
  }

  export type InstituicaoEspiritaCreateManyAtualizadoPorInput = {
    id?: number
    nome: string
    nome_CNPJ?: string | null
    estado?: string | null
    cidade?: string | null
    bairro?: string | null
    logradouro?: string | null
    numero?: string | null
    complemento?: string | null
    telefone?: string | null
    email?: string | null
    createdAt?: Date | string
    updatedAt?: Date | string
    criadoPorId?: number | null
    sigla: string
    CEU?: string | null
    dia?: string | null
    horario?: string | null
    CNPJ: string
  }

  export type InstituicaoEspiritaCreateManyCriadoPorInput = {
    id?: number
    nome: string
    nome_CNPJ?: string | null
    estado?: string | null
    cidade?: string | null
    bairro?: string | null
    logradouro?: string | null
    numero?: string | null
    complemento?: string | null
    telefone?: string | null
    email?: string | null
    createdAt?: Date | string
    updatedAt?: Date | string
    sigla: string
    CEU?: string | null
    dia?: string | null
    horario?: string | null
    atualizadoPorId?: number | null
    CNPJ: string
  }

  export type Participante2025CreateManyUserInput = {
    id?: string
    nomeCompleto: string
    nomeCracha?: string | null
    cpf?: string | null
    nomeSocial?: string | null
    dataNascimento: Date | string
    sexo: string
    email: string
    telefone: string
    nomeCompletoResponsavel?: string | null
    documentoResponsavel?: string | null
    telefoneResponsavel?: string | null
    linkPagamento?: string | null
    idade?: number | null
    valor?: number | null
    statusPagamento?: string | null
    tipoParticipacao: $Enums.TipoParticipacao
    comissao?: string | null
    tamanhoCamisa?: string | null
    cep: string
    estado?: string | null
    cidade?: string | null
    bairro?: string | null
    logradouro?: string | null
    numero?: string | null
    complemento?: string | null
    outroGenero?: string | null
    medicacao?: string | null
    alergia?: string | null
    outrasInformacoes?: string | null
    createdAt?: Date | string
    updatedAt?: Date | string
    IE: string
    instituicaoId?: number | null
    vegetariano?: string
    camisa?: boolean | null
    primeiraComejaca?: boolean | null
    deficienciaAuditiva?: boolean | null
    deficienciaAutismo?: boolean | null
    deficienciaIntelectual?: boolean | null
    deficienciaParalisiaCerebral?: boolean | null
    deficienciaVisual?: boolean | null
    deficienciaFisica?: boolean | null
    deficienciaOutra?: boolean | null
    deficienciaOutraDescricao?: string | null
    otherInstitution?: string | null
  }

  export type PasswordResetTokenCreateManyUserInput = {
    id?: number
    token: string
    expiresAt: Date | string
    createdAt?: Date | string
  }

  export type InstituicaoEspiritaUpdateWithoutAtualizadoPorInput = {
    nome?: StringFieldUpdateOperationsInput | string
    nome_CNPJ?: NullableStringFieldUpdateOperationsInput | string | null
    estado?: NullableStringFieldUpdateOperationsInput | string | null
    cidade?: NullableStringFieldUpdateOperationsInput | string | null
    bairro?: NullableStringFieldUpdateOperationsInput | string | null
    logradouro?: NullableStringFieldUpdateOperationsInput | string | null
    numero?: NullableStringFieldUpdateOperationsInput | string | null
    complemento?: NullableStringFieldUpdateOperationsInput | string | null
    telefone?: NullableStringFieldUpdateOperationsInput | string | null
    email?: NullableStringFieldUpdateOperationsInput | string | null
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    sigla?: StringFieldUpdateOperationsInput | string
    CEU?: NullableStringFieldUpdateOperationsInput | string | null
    dia?: NullableStringFieldUpdateOperationsInput | string | null
    horario?: NullableStringFieldUpdateOperationsInput | string | null
    CNPJ?: StringFieldUpdateOperationsInput | string
    criadoPor?: UsersUpdateOneWithoutInstituicoesCriadasNestedInput
    Participante2025?: Participante2025UpdateManyWithoutInstituicaoNestedInput
    Users?: UsersUpdateManyWithoutInstituicoesNestedInput
  }

  export type InstituicaoEspiritaUncheckedUpdateWithoutAtualizadoPorInput = {
    id?: IntFieldUpdateOperationsInput | number
    nome?: StringFieldUpdateOperationsInput | string
    nome_CNPJ?: NullableStringFieldUpdateOperationsInput | string | null
    estado?: NullableStringFieldUpdateOperationsInput | string | null
    cidade?: NullableStringFieldUpdateOperationsInput | string | null
    bairro?: NullableStringFieldUpdateOperationsInput | string | null
    logradouro?: NullableStringFieldUpdateOperationsInput | string | null
    numero?: NullableStringFieldUpdateOperationsInput | string | null
    complemento?: NullableStringFieldUpdateOperationsInput | string | null
    telefone?: NullableStringFieldUpdateOperationsInput | string | null
    email?: NullableStringFieldUpdateOperationsInput | string | null
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    criadoPorId?: NullableIntFieldUpdateOperationsInput | number | null
    sigla?: StringFieldUpdateOperationsInput | string
    CEU?: NullableStringFieldUpdateOperationsInput | string | null
    dia?: NullableStringFieldUpdateOperationsInput | string | null
    horario?: NullableStringFieldUpdateOperationsInput | string | null
    CNPJ?: StringFieldUpdateOperationsInput | string
    Participante2025?: Participante2025UncheckedUpdateManyWithoutInstituicaoNestedInput
    Users?: UsersUncheckedUpdateManyWithoutInstituicoesNestedInput
  }

  export type InstituicaoEspiritaUncheckedUpdateManyWithoutAtualizadoPorInput = {
    id?: IntFieldUpdateOperationsInput | number
    nome?: StringFieldUpdateOperationsInput | string
    nome_CNPJ?: NullableStringFieldUpdateOperationsInput | string | null
    estado?: NullableStringFieldUpdateOperationsInput | string | null
    cidade?: NullableStringFieldUpdateOperationsInput | string | null
    bairro?: NullableStringFieldUpdateOperationsInput | string | null
    logradouro?: NullableStringFieldUpdateOperationsInput | string | null
    numero?: NullableStringFieldUpdateOperationsInput | string | null
    complemento?: NullableStringFieldUpdateOperationsInput | string | null
    telefone?: NullableStringFieldUpdateOperationsInput | string | null
    email?: NullableStringFieldUpdateOperationsInput | string | null
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    criadoPorId?: NullableIntFieldUpdateOperationsInput | number | null
    sigla?: StringFieldUpdateOperationsInput | string
    CEU?: NullableStringFieldUpdateOperationsInput | string | null
    dia?: NullableStringFieldUpdateOperationsInput | string | null
    horario?: NullableStringFieldUpdateOperationsInput | string | null
    CNPJ?: StringFieldUpdateOperationsInput | string
  }

  export type InstituicaoEspiritaUpdateWithoutCriadoPorInput = {
    nome?: StringFieldUpdateOperationsInput | string
    nome_CNPJ?: NullableStringFieldUpdateOperationsInput | string | null
    estado?: NullableStringFieldUpdateOperationsInput | string | null
    cidade?: NullableStringFieldUpdateOperationsInput | string | null
    bairro?: NullableStringFieldUpdateOperationsInput | string | null
    logradouro?: NullableStringFieldUpdateOperationsInput | string | null
    numero?: NullableStringFieldUpdateOperationsInput | string | null
    complemento?: NullableStringFieldUpdateOperationsInput | string | null
    telefone?: NullableStringFieldUpdateOperationsInput | string | null
    email?: NullableStringFieldUpdateOperationsInput | string | null
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    sigla?: StringFieldUpdateOperationsInput | string
    CEU?: NullableStringFieldUpdateOperationsInput | string | null
    dia?: NullableStringFieldUpdateOperationsInput | string | null
    horario?: NullableStringFieldUpdateOperationsInput | string | null
    CNPJ?: StringFieldUpdateOperationsInput | string
    atualizadoPor?: UsersUpdateOneWithoutInstituicoesAtualizadasNestedInput
    Participante2025?: Participante2025UpdateManyWithoutInstituicaoNestedInput
    Users?: UsersUpdateManyWithoutInstituicoesNestedInput
  }

  export type InstituicaoEspiritaUncheckedUpdateWithoutCriadoPorInput = {
    id?: IntFieldUpdateOperationsInput | number
    nome?: StringFieldUpdateOperationsInput | string
    nome_CNPJ?: NullableStringFieldUpdateOperationsInput | string | null
    estado?: NullableStringFieldUpdateOperationsInput | string | null
    cidade?: NullableStringFieldUpdateOperationsInput | string | null
    bairro?: NullableStringFieldUpdateOperationsInput | string | null
    logradouro?: NullableStringFieldUpdateOperationsInput | string | null
    numero?: NullableStringFieldUpdateOperationsInput | string | null
    complemento?: NullableStringFieldUpdateOperationsInput | string | null
    telefone?: NullableStringFieldUpdateOperationsInput | string | null
    email?: NullableStringFieldUpdateOperationsInput | string | null
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    sigla?: StringFieldUpdateOperationsInput | string
    CEU?: NullableStringFieldUpdateOperationsInput | string | null
    dia?: NullableStringFieldUpdateOperationsInput | string | null
    horario?: NullableStringFieldUpdateOperationsInput | string | null
    atualizadoPorId?: NullableIntFieldUpdateOperationsInput | number | null
    CNPJ?: StringFieldUpdateOperationsInput | string
    Participante2025?: Participante2025UncheckedUpdateManyWithoutInstituicaoNestedInput
    Users?: UsersUncheckedUpdateManyWithoutInstituicoesNestedInput
  }

  export type InstituicaoEspiritaUncheckedUpdateManyWithoutCriadoPorInput = {
    id?: IntFieldUpdateOperationsInput | number
    nome?: StringFieldUpdateOperationsInput | string
    nome_CNPJ?: NullableStringFieldUpdateOperationsInput | string | null
    estado?: NullableStringFieldUpdateOperationsInput | string | null
    cidade?: NullableStringFieldUpdateOperationsInput | string | null
    bairro?: NullableStringFieldUpdateOperationsInput | string | null
    logradouro?: NullableStringFieldUpdateOperationsInput | string | null
    numero?: NullableStringFieldUpdateOperationsInput | string | null
    complemento?: NullableStringFieldUpdateOperationsInput | string | null
    telefone?: NullableStringFieldUpdateOperationsInput | string | null
    email?: NullableStringFieldUpdateOperationsInput | string | null
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    sigla?: StringFieldUpdateOperationsInput | string
    CEU?: NullableStringFieldUpdateOperationsInput | string | null
    dia?: NullableStringFieldUpdateOperationsInput | string | null
    horario?: NullableStringFieldUpdateOperationsInput | string | null
    atualizadoPorId?: NullableIntFieldUpdateOperationsInput | number | null
    CNPJ?: StringFieldUpdateOperationsInput | string
  }

  export type Participante2025UpdateWithoutUserInput = {
    id?: StringFieldUpdateOperationsInput | string
    nomeCompleto?: StringFieldUpdateOperationsInput | string
    nomeCracha?: NullableStringFieldUpdateOperationsInput | string | null
    cpf?: NullableStringFieldUpdateOperationsInput | string | null
    nomeSocial?: NullableStringFieldUpdateOperationsInput | string | null
    dataNascimento?: DateTimeFieldUpdateOperationsInput | Date | string
    sexo?: StringFieldUpdateOperationsInput | string
    email?: StringFieldUpdateOperationsInput | string
    telefone?: StringFieldUpdateOperationsInput | string
    nomeCompletoResponsavel?: NullableStringFieldUpdateOperationsInput | string | null
    documentoResponsavel?: NullableStringFieldUpdateOperationsInput | string | null
    telefoneResponsavel?: NullableStringFieldUpdateOperationsInput | string | null
    linkPagamento?: NullableStringFieldUpdateOperationsInput | string | null
    idade?: NullableIntFieldUpdateOperationsInput | number | null
    valor?: NullableFloatFieldUpdateOperationsInput | number | null
    statusPagamento?: NullableStringFieldUpdateOperationsInput | string | null
    tipoParticipacao?: EnumTipoParticipacaoFieldUpdateOperationsInput | $Enums.TipoParticipacao
    comissao?: NullableStringFieldUpdateOperationsInput | string | null
    tamanhoCamisa?: NullableStringFieldUpdateOperationsInput | string | null
    cep?: StringFieldUpdateOperationsInput | string
    estado?: NullableStringFieldUpdateOperationsInput | string | null
    cidade?: NullableStringFieldUpdateOperationsInput | string | null
    bairro?: NullableStringFieldUpdateOperationsInput | string | null
    logradouro?: NullableStringFieldUpdateOperationsInput | string | null
    numero?: NullableStringFieldUpdateOperationsInput | string | null
    complemento?: NullableStringFieldUpdateOperationsInput | string | null
    outroGenero?: NullableStringFieldUpdateOperationsInput | string | null
    medicacao?: NullableStringFieldUpdateOperationsInput | string | null
    alergia?: NullableStringFieldUpdateOperationsInput | string | null
    outrasInformacoes?: NullableStringFieldUpdateOperationsInput | string | null
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    IE?: StringFieldUpdateOperationsInput | string
    vegetariano?: StringFieldUpdateOperationsInput | string
    camisa?: NullableBoolFieldUpdateOperationsInput | boolean | null
    primeiraComejaca?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaAuditiva?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaAutismo?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaIntelectual?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaParalisiaCerebral?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaVisual?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaFisica?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaOutra?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaOutraDescricao?: NullableStringFieldUpdateOperationsInput | string | null
    otherInstitution?: NullableStringFieldUpdateOperationsInput | string | null
    instituicao?: InstituicaoEspiritaUpdateOneWithoutParticipante2025NestedInput
  }

  export type Participante2025UncheckedUpdateWithoutUserInput = {
    id?: StringFieldUpdateOperationsInput | string
    nomeCompleto?: StringFieldUpdateOperationsInput | string
    nomeCracha?: NullableStringFieldUpdateOperationsInput | string | null
    cpf?: NullableStringFieldUpdateOperationsInput | string | null
    nomeSocial?: NullableStringFieldUpdateOperationsInput | string | null
    dataNascimento?: DateTimeFieldUpdateOperationsInput | Date | string
    sexo?: StringFieldUpdateOperationsInput | string
    email?: StringFieldUpdateOperationsInput | string
    telefone?: StringFieldUpdateOperationsInput | string
    nomeCompletoResponsavel?: NullableStringFieldUpdateOperationsInput | string | null
    documentoResponsavel?: NullableStringFieldUpdateOperationsInput | string | null
    telefoneResponsavel?: NullableStringFieldUpdateOperationsInput | string | null
    linkPagamento?: NullableStringFieldUpdateOperationsInput | string | null
    idade?: NullableIntFieldUpdateOperationsInput | number | null
    valor?: NullableFloatFieldUpdateOperationsInput | number | null
    statusPagamento?: NullableStringFieldUpdateOperationsInput | string | null
    tipoParticipacao?: EnumTipoParticipacaoFieldUpdateOperationsInput | $Enums.TipoParticipacao
    comissao?: NullableStringFieldUpdateOperationsInput | string | null
    tamanhoCamisa?: NullableStringFieldUpdateOperationsInput | string | null
    cep?: StringFieldUpdateOperationsInput | string
    estado?: NullableStringFieldUpdateOperationsInput | string | null
    cidade?: NullableStringFieldUpdateOperationsInput | string | null
    bairro?: NullableStringFieldUpdateOperationsInput | string | null
    logradouro?: NullableStringFieldUpdateOperationsInput | string | null
    numero?: NullableStringFieldUpdateOperationsInput | string | null
    complemento?: NullableStringFieldUpdateOperationsInput | string | null
    outroGenero?: NullableStringFieldUpdateOperationsInput | string | null
    medicacao?: NullableStringFieldUpdateOperationsInput | string | null
    alergia?: NullableStringFieldUpdateOperationsInput | string | null
    outrasInformacoes?: NullableStringFieldUpdateOperationsInput | string | null
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    IE?: StringFieldUpdateOperationsInput | string
    instituicaoId?: NullableIntFieldUpdateOperationsInput | number | null
    vegetariano?: StringFieldUpdateOperationsInput | string
    camisa?: NullableBoolFieldUpdateOperationsInput | boolean | null
    primeiraComejaca?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaAuditiva?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaAutismo?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaIntelectual?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaParalisiaCerebral?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaVisual?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaFisica?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaOutra?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaOutraDescricao?: NullableStringFieldUpdateOperationsInput | string | null
    otherInstitution?: NullableStringFieldUpdateOperationsInput | string | null
  }

  export type Participante2025UncheckedUpdateManyWithoutUserInput = {
    id?: StringFieldUpdateOperationsInput | string
    nomeCompleto?: StringFieldUpdateOperationsInput | string
    nomeCracha?: NullableStringFieldUpdateOperationsInput | string | null
    cpf?: NullableStringFieldUpdateOperationsInput | string | null
    nomeSocial?: NullableStringFieldUpdateOperationsInput | string | null
    dataNascimento?: DateTimeFieldUpdateOperationsInput | Date | string
    sexo?: StringFieldUpdateOperationsInput | string
    email?: StringFieldUpdateOperationsInput | string
    telefone?: StringFieldUpdateOperationsInput | string
    nomeCompletoResponsavel?: NullableStringFieldUpdateOperationsInput | string | null
    documentoResponsavel?: NullableStringFieldUpdateOperationsInput | string | null
    telefoneResponsavel?: NullableStringFieldUpdateOperationsInput | string | null
    linkPagamento?: NullableStringFieldUpdateOperationsInput | string | null
    idade?: NullableIntFieldUpdateOperationsInput | number | null
    valor?: NullableFloatFieldUpdateOperationsInput | number | null
    statusPagamento?: NullableStringFieldUpdateOperationsInput | string | null
    tipoParticipacao?: EnumTipoParticipacaoFieldUpdateOperationsInput | $Enums.TipoParticipacao
    comissao?: NullableStringFieldUpdateOperationsInput | string | null
    tamanhoCamisa?: NullableStringFieldUpdateOperationsInput | string | null
    cep?: StringFieldUpdateOperationsInput | string
    estado?: NullableStringFieldUpdateOperationsInput | string | null
    cidade?: NullableStringFieldUpdateOperationsInput | string | null
    bairro?: NullableStringFieldUpdateOperationsInput | string | null
    logradouro?: NullableStringFieldUpdateOperationsInput | string | null
    numero?: NullableStringFieldUpdateOperationsInput | string | null
    complemento?: NullableStringFieldUpdateOperationsInput | string | null
    outroGenero?: NullableStringFieldUpdateOperationsInput | string | null
    medicacao?: NullableStringFieldUpdateOperationsInput | string | null
    alergia?: NullableStringFieldUpdateOperationsInput | string | null
    outrasInformacoes?: NullableStringFieldUpdateOperationsInput | string | null
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    IE?: StringFieldUpdateOperationsInput | string
    instituicaoId?: NullableIntFieldUpdateOperationsInput | number | null
    vegetariano?: StringFieldUpdateOperationsInput | string
    camisa?: NullableBoolFieldUpdateOperationsInput | boolean | null
    primeiraComejaca?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaAuditiva?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaAutismo?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaIntelectual?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaParalisiaCerebral?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaVisual?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaFisica?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaOutra?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaOutraDescricao?: NullableStringFieldUpdateOperationsInput | string | null
    otherInstitution?: NullableStringFieldUpdateOperationsInput | string | null
  }

  export type InstituicaoEspiritaUpdateWithoutUsersInput = {
    nome?: StringFieldUpdateOperationsInput | string
    nome_CNPJ?: NullableStringFieldUpdateOperationsInput | string | null
    estado?: NullableStringFieldUpdateOperationsInput | string | null
    cidade?: NullableStringFieldUpdateOperationsInput | string | null
    bairro?: NullableStringFieldUpdateOperationsInput | string | null
    logradouro?: NullableStringFieldUpdateOperationsInput | string | null
    numero?: NullableStringFieldUpdateOperationsInput | string | null
    complemento?: NullableStringFieldUpdateOperationsInput | string | null
    telefone?: NullableStringFieldUpdateOperationsInput | string | null
    email?: NullableStringFieldUpdateOperationsInput | string | null
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    sigla?: StringFieldUpdateOperationsInput | string
    CEU?: NullableStringFieldUpdateOperationsInput | string | null
    dia?: NullableStringFieldUpdateOperationsInput | string | null
    horario?: NullableStringFieldUpdateOperationsInput | string | null
    CNPJ?: StringFieldUpdateOperationsInput | string
    atualizadoPor?: UsersUpdateOneWithoutInstituicoesAtualizadasNestedInput
    criadoPor?: UsersUpdateOneWithoutInstituicoesCriadasNestedInput
    Participante2025?: Participante2025UpdateManyWithoutInstituicaoNestedInput
  }

  export type InstituicaoEspiritaUncheckedUpdateWithoutUsersInput = {
    id?: IntFieldUpdateOperationsInput | number
    nome?: StringFieldUpdateOperationsInput | string
    nome_CNPJ?: NullableStringFieldUpdateOperationsInput | string | null
    estado?: NullableStringFieldUpdateOperationsInput | string | null
    cidade?: NullableStringFieldUpdateOperationsInput | string | null
    bairro?: NullableStringFieldUpdateOperationsInput | string | null
    logradouro?: NullableStringFieldUpdateOperationsInput | string | null
    numero?: NullableStringFieldUpdateOperationsInput | string | null
    complemento?: NullableStringFieldUpdateOperationsInput | string | null
    telefone?: NullableStringFieldUpdateOperationsInput | string | null
    email?: NullableStringFieldUpdateOperationsInput | string | null
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    criadoPorId?: NullableIntFieldUpdateOperationsInput | number | null
    sigla?: StringFieldUpdateOperationsInput | string
    CEU?: NullableStringFieldUpdateOperationsInput | string | null
    dia?: NullableStringFieldUpdateOperationsInput | string | null
    horario?: NullableStringFieldUpdateOperationsInput | string | null
    atualizadoPorId?: NullableIntFieldUpdateOperationsInput | number | null
    CNPJ?: StringFieldUpdateOperationsInput | string
    Participante2025?: Participante2025UncheckedUpdateManyWithoutInstituicaoNestedInput
  }

  export type InstituicaoEspiritaUncheckedUpdateManyWithoutUsersInput = {
    id?: IntFieldUpdateOperationsInput | number
    nome?: StringFieldUpdateOperationsInput | string
    nome_CNPJ?: NullableStringFieldUpdateOperationsInput | string | null
    estado?: NullableStringFieldUpdateOperationsInput | string | null
    cidade?: NullableStringFieldUpdateOperationsInput | string | null
    bairro?: NullableStringFieldUpdateOperationsInput | string | null
    logradouro?: NullableStringFieldUpdateOperationsInput | string | null
    numero?: NullableStringFieldUpdateOperationsInput | string | null
    complemento?: NullableStringFieldUpdateOperationsInput | string | null
    telefone?: NullableStringFieldUpdateOperationsInput | string | null
    email?: NullableStringFieldUpdateOperationsInput | string | null
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    criadoPorId?: NullableIntFieldUpdateOperationsInput | number | null
    sigla?: StringFieldUpdateOperationsInput | string
    CEU?: NullableStringFieldUpdateOperationsInput | string | null
    dia?: NullableStringFieldUpdateOperationsInput | string | null
    horario?: NullableStringFieldUpdateOperationsInput | string | null
    atualizadoPorId?: NullableIntFieldUpdateOperationsInput | number | null
    CNPJ?: StringFieldUpdateOperationsInput | string
  }

  export type PasswordResetTokenUpdateWithoutUserInput = {
    token?: StringFieldUpdateOperationsInput | string
    expiresAt?: DateTimeFieldUpdateOperationsInput | Date | string
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
  }

  export type PasswordResetTokenUncheckedUpdateWithoutUserInput = {
    id?: IntFieldUpdateOperationsInput | number
    token?: StringFieldUpdateOperationsInput | string
    expiresAt?: DateTimeFieldUpdateOperationsInput | Date | string
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
  }

  export type PasswordResetTokenUncheckedUpdateManyWithoutUserInput = {
    id?: IntFieldUpdateOperationsInput | number
    token?: StringFieldUpdateOperationsInput | string
    expiresAt?: DateTimeFieldUpdateOperationsInput | Date | string
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
  }

  export type Participante2025CreateManyInstituicaoInput = {
    id?: string
    nomeCompleto: string
    nomeCracha?: string | null
    cpf?: string | null
    nomeSocial?: string | null
    dataNascimento: Date | string
    sexo: string
    email: string
    telefone: string
    nomeCompletoResponsavel?: string | null
    documentoResponsavel?: string | null
    telefoneResponsavel?: string | null
    linkPagamento?: string | null
    idade?: number | null
    valor?: number | null
    statusPagamento?: string | null
    tipoParticipacao: $Enums.TipoParticipacao
    comissao?: string | null
    tamanhoCamisa?: string | null
    cep: string
    estado?: string | null
    cidade?: string | null
    bairro?: string | null
    logradouro?: string | null
    numero?: string | null
    complemento?: string | null
    outroGenero?: string | null
    medicacao?: string | null
    alergia?: string | null
    outrasInformacoes?: string | null
    userId?: number | null
    createdAt?: Date | string
    updatedAt?: Date | string
    IE: string
    vegetariano?: string
    camisa?: boolean | null
    primeiraComejaca?: boolean | null
    deficienciaAuditiva?: boolean | null
    deficienciaAutismo?: boolean | null
    deficienciaIntelectual?: boolean | null
    deficienciaParalisiaCerebral?: boolean | null
    deficienciaVisual?: boolean | null
    deficienciaFisica?: boolean | null
    deficienciaOutra?: boolean | null
    deficienciaOutraDescricao?: string | null
    otherInstitution?: string | null
  }

  export type Participante2025UpdateWithoutInstituicaoInput = {
    id?: StringFieldUpdateOperationsInput | string
    nomeCompleto?: StringFieldUpdateOperationsInput | string
    nomeCracha?: NullableStringFieldUpdateOperationsInput | string | null
    cpf?: NullableStringFieldUpdateOperationsInput | string | null
    nomeSocial?: NullableStringFieldUpdateOperationsInput | string | null
    dataNascimento?: DateTimeFieldUpdateOperationsInput | Date | string
    sexo?: StringFieldUpdateOperationsInput | string
    email?: StringFieldUpdateOperationsInput | string
    telefone?: StringFieldUpdateOperationsInput | string
    nomeCompletoResponsavel?: NullableStringFieldUpdateOperationsInput | string | null
    documentoResponsavel?: NullableStringFieldUpdateOperationsInput | string | null
    telefoneResponsavel?: NullableStringFieldUpdateOperationsInput | string | null
    linkPagamento?: NullableStringFieldUpdateOperationsInput | string | null
    idade?: NullableIntFieldUpdateOperationsInput | number | null
    valor?: NullableFloatFieldUpdateOperationsInput | number | null
    statusPagamento?: NullableStringFieldUpdateOperationsInput | string | null
    tipoParticipacao?: EnumTipoParticipacaoFieldUpdateOperationsInput | $Enums.TipoParticipacao
    comissao?: NullableStringFieldUpdateOperationsInput | string | null
    tamanhoCamisa?: NullableStringFieldUpdateOperationsInput | string | null
    cep?: StringFieldUpdateOperationsInput | string
    estado?: NullableStringFieldUpdateOperationsInput | string | null
    cidade?: NullableStringFieldUpdateOperationsInput | string | null
    bairro?: NullableStringFieldUpdateOperationsInput | string | null
    logradouro?: NullableStringFieldUpdateOperationsInput | string | null
    numero?: NullableStringFieldUpdateOperationsInput | string | null
    complemento?: NullableStringFieldUpdateOperationsInput | string | null
    outroGenero?: NullableStringFieldUpdateOperationsInput | string | null
    medicacao?: NullableStringFieldUpdateOperationsInput | string | null
    alergia?: NullableStringFieldUpdateOperationsInput | string | null
    outrasInformacoes?: NullableStringFieldUpdateOperationsInput | string | null
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    IE?: StringFieldUpdateOperationsInput | string
    vegetariano?: StringFieldUpdateOperationsInput | string
    camisa?: NullableBoolFieldUpdateOperationsInput | boolean | null
    primeiraComejaca?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaAuditiva?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaAutismo?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaIntelectual?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaParalisiaCerebral?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaVisual?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaFisica?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaOutra?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaOutraDescricao?: NullableStringFieldUpdateOperationsInput | string | null
    otherInstitution?: NullableStringFieldUpdateOperationsInput | string | null
    user?: UsersUpdateOneWithoutParticipante2025NestedInput
  }

  export type Participante2025UncheckedUpdateWithoutInstituicaoInput = {
    id?: StringFieldUpdateOperationsInput | string
    nomeCompleto?: StringFieldUpdateOperationsInput | string
    nomeCracha?: NullableStringFieldUpdateOperationsInput | string | null
    cpf?: NullableStringFieldUpdateOperationsInput | string | null
    nomeSocial?: NullableStringFieldUpdateOperationsInput | string | null
    dataNascimento?: DateTimeFieldUpdateOperationsInput | Date | string
    sexo?: StringFieldUpdateOperationsInput | string
    email?: StringFieldUpdateOperationsInput | string
    telefone?: StringFieldUpdateOperationsInput | string
    nomeCompletoResponsavel?: NullableStringFieldUpdateOperationsInput | string | null
    documentoResponsavel?: NullableStringFieldUpdateOperationsInput | string | null
    telefoneResponsavel?: NullableStringFieldUpdateOperationsInput | string | null
    linkPagamento?: NullableStringFieldUpdateOperationsInput | string | null
    idade?: NullableIntFieldUpdateOperationsInput | number | null
    valor?: NullableFloatFieldUpdateOperationsInput | number | null
    statusPagamento?: NullableStringFieldUpdateOperationsInput | string | null
    tipoParticipacao?: EnumTipoParticipacaoFieldUpdateOperationsInput | $Enums.TipoParticipacao
    comissao?: NullableStringFieldUpdateOperationsInput | string | null
    tamanhoCamisa?: NullableStringFieldUpdateOperationsInput | string | null
    cep?: StringFieldUpdateOperationsInput | string
    estado?: NullableStringFieldUpdateOperationsInput | string | null
    cidade?: NullableStringFieldUpdateOperationsInput | string | null
    bairro?: NullableStringFieldUpdateOperationsInput | string | null
    logradouro?: NullableStringFieldUpdateOperationsInput | string | null
    numero?: NullableStringFieldUpdateOperationsInput | string | null
    complemento?: NullableStringFieldUpdateOperationsInput | string | null
    outroGenero?: NullableStringFieldUpdateOperationsInput | string | null
    medicacao?: NullableStringFieldUpdateOperationsInput | string | null
    alergia?: NullableStringFieldUpdateOperationsInput | string | null
    outrasInformacoes?: NullableStringFieldUpdateOperationsInput | string | null
    userId?: NullableIntFieldUpdateOperationsInput | number | null
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    IE?: StringFieldUpdateOperationsInput | string
    vegetariano?: StringFieldUpdateOperationsInput | string
    camisa?: NullableBoolFieldUpdateOperationsInput | boolean | null
    primeiraComejaca?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaAuditiva?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaAutismo?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaIntelectual?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaParalisiaCerebral?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaVisual?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaFisica?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaOutra?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaOutraDescricao?: NullableStringFieldUpdateOperationsInput | string | null
    otherInstitution?: NullableStringFieldUpdateOperationsInput | string | null
  }

  export type Participante2025UncheckedUpdateManyWithoutInstituicaoInput = {
    id?: StringFieldUpdateOperationsInput | string
    nomeCompleto?: StringFieldUpdateOperationsInput | string
    nomeCracha?: NullableStringFieldUpdateOperationsInput | string | null
    cpf?: NullableStringFieldUpdateOperationsInput | string | null
    nomeSocial?: NullableStringFieldUpdateOperationsInput | string | null
    dataNascimento?: DateTimeFieldUpdateOperationsInput | Date | string
    sexo?: StringFieldUpdateOperationsInput | string
    email?: StringFieldUpdateOperationsInput | string
    telefone?: StringFieldUpdateOperationsInput | string
    nomeCompletoResponsavel?: NullableStringFieldUpdateOperationsInput | string | null
    documentoResponsavel?: NullableStringFieldUpdateOperationsInput | string | null
    telefoneResponsavel?: NullableStringFieldUpdateOperationsInput | string | null
    linkPagamento?: NullableStringFieldUpdateOperationsInput | string | null
    idade?: NullableIntFieldUpdateOperationsInput | number | null
    valor?: NullableFloatFieldUpdateOperationsInput | number | null
    statusPagamento?: NullableStringFieldUpdateOperationsInput | string | null
    tipoParticipacao?: EnumTipoParticipacaoFieldUpdateOperationsInput | $Enums.TipoParticipacao
    comissao?: NullableStringFieldUpdateOperationsInput | string | null
    tamanhoCamisa?: NullableStringFieldUpdateOperationsInput | string | null
    cep?: StringFieldUpdateOperationsInput | string
    estado?: NullableStringFieldUpdateOperationsInput | string | null
    cidade?: NullableStringFieldUpdateOperationsInput | string | null
    bairro?: NullableStringFieldUpdateOperationsInput | string | null
    logradouro?: NullableStringFieldUpdateOperationsInput | string | null
    numero?: NullableStringFieldUpdateOperationsInput | string | null
    complemento?: NullableStringFieldUpdateOperationsInput | string | null
    outroGenero?: NullableStringFieldUpdateOperationsInput | string | null
    medicacao?: NullableStringFieldUpdateOperationsInput | string | null
    alergia?: NullableStringFieldUpdateOperationsInput | string | null
    outrasInformacoes?: NullableStringFieldUpdateOperationsInput | string | null
    userId?: NullableIntFieldUpdateOperationsInput | number | null
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    IE?: StringFieldUpdateOperationsInput | string
    vegetariano?: StringFieldUpdateOperationsInput | string
    camisa?: NullableBoolFieldUpdateOperationsInput | boolean | null
    primeiraComejaca?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaAuditiva?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaAutismo?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaIntelectual?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaParalisiaCerebral?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaVisual?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaFisica?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaOutra?: NullableBoolFieldUpdateOperationsInput | boolean | null
    deficienciaOutraDescricao?: NullableStringFieldUpdateOperationsInput | string | null
    otherInstitution?: NullableStringFieldUpdateOperationsInput | string | null
  }

  export type UsersUpdateWithoutInstituicoesInput = {
    name?: StringFieldUpdateOperationsInput | string
    email?: StringFieldUpdateOperationsInput | string
    password?: StringFieldUpdateOperationsInput | string
    isVerified?: BoolFieldUpdateOperationsInput | boolean
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    verificationCode?: NullableStringFieldUpdateOperationsInput | string | null
    verificationCodeExpiration?: NullableDateTimeFieldUpdateOperationsInput | Date | string | null
    lastVerificationRequest?: DateTimeFieldUpdateOperationsInput | Date | string
    role?: EnumRoleFieldUpdateOperationsInput | $Enums.Role
    comunicacaocomejaca?: NullableStringFieldUpdateOperationsInput | string | null
    comunicacaomovimento?: NullableStringFieldUpdateOperationsInput | string | null
    telefone?: NullableStringFieldUpdateOperationsInput | string | null
    resetTokenVersion?: IntFieldUpdateOperationsInput | number
    instituicoesAtualizadas?: InstituicaoEspiritaUpdateManyWithoutAtualizadoPorNestedInput
    instituicoesCriadas?: InstituicaoEspiritaUpdateManyWithoutCriadoPorNestedInput
    Participante2025?: Participante2025UpdateManyWithoutUserNestedInput
    passwordResetTokens?: PasswordResetTokenUpdateManyWithoutUserNestedInput
  }

  export type UsersUncheckedUpdateWithoutInstituicoesInput = {
    id?: IntFieldUpdateOperationsInput | number
    name?: StringFieldUpdateOperationsInput | string
    email?: StringFieldUpdateOperationsInput | string
    password?: StringFieldUpdateOperationsInput | string
    isVerified?: BoolFieldUpdateOperationsInput | boolean
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    verificationCode?: NullableStringFieldUpdateOperationsInput | string | null
    verificationCodeExpiration?: NullableDateTimeFieldUpdateOperationsInput | Date | string | null
    lastVerificationRequest?: DateTimeFieldUpdateOperationsInput | Date | string
    role?: EnumRoleFieldUpdateOperationsInput | $Enums.Role
    comunicacaocomejaca?: NullableStringFieldUpdateOperationsInput | string | null
    comunicacaomovimento?: NullableStringFieldUpdateOperationsInput | string | null
    telefone?: NullableStringFieldUpdateOperationsInput | string | null
    resetTokenVersion?: IntFieldUpdateOperationsInput | number
    instituicoesAtualizadas?: InstituicaoEspiritaUncheckedUpdateManyWithoutAtualizadoPorNestedInput
    instituicoesCriadas?: InstituicaoEspiritaUncheckedUpdateManyWithoutCriadoPorNestedInput
    Participante2025?: Participante2025UncheckedUpdateManyWithoutUserNestedInput
    passwordResetTokens?: PasswordResetTokenUncheckedUpdateManyWithoutUserNestedInput
  }

  export type UsersUncheckedUpdateManyWithoutInstituicoesInput = {
    id?: IntFieldUpdateOperationsInput | number
    name?: StringFieldUpdateOperationsInput | string
    email?: StringFieldUpdateOperationsInput | string
    password?: StringFieldUpdateOperationsInput | string
    isVerified?: BoolFieldUpdateOperationsInput | boolean
    createdAt?: DateTimeFieldUpdateOperationsInput | Date | string
    updatedAt?: DateTimeFieldUpdateOperationsInput | Date | string
    verificationCode?: NullableStringFieldUpdateOperationsInput | string | null
    verificationCodeExpiration?: NullableDateTimeFieldUpdateOperationsInput | Date | string | null
    lastVerificationRequest?: DateTimeFieldUpdateOperationsInput | Date | string
    role?: EnumRoleFieldUpdateOperationsInput | $Enums.Role
    comunicacaocomejaca?: NullableStringFieldUpdateOperationsInput | string | null
    comunicacaomovimento?: NullableStringFieldUpdateOperationsInput | string | null
    telefone?: NullableStringFieldUpdateOperationsInput | string | null
    resetTokenVersion?: IntFieldUpdateOperationsInput | number
  }



  /**
   * Batch Payload for updateMany & deleteMany & createMany
   */

  export type BatchPayload = {
    count: number
  }

  /**
   * DMMF
   */
  export const dmmf: runtime.BaseDMMF
}