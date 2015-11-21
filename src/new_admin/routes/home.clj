(ns new-admin.routes.home
  (:require [new-admin.layout :as layout]
            [compojure.core :refer [defroutes GET POST]]
            [ring.util.http-response :refer [ok]]
            [clojure.java.io :as io]
            [new-admin.db.core :as db]
            [ring.util.response :refer [redirect response]]
            [buddy.hashers :as hashers]
            [bouncer.core :as b]
            [bouncer.validators :as v]
            [buddy.auth :refer [authenticated?]]
            [crypto.random :refer [url-part]]
            [clj-time.core :as t]
            [clj-time.coerce :as c]
            [clj-time.local :as l]
            ))



;(defn user-signup-page
;  [request]
;  (layout/render
;    "user-signup.html"
;    request))
;;premiere version avant ajout de la gestion d'erreurs

;this is a handler, it takes a request and gives a response
;the response will render a template with an associated context-map

(defn user-signup-page
  [{:keys [flash]}]
  (layout/render
    "user-signup.html"
    flash))


(defn user-exists?
  [email]
  (:exists (first (db/exists_user? {:email email}))))


(defn validate-user-signup
  [params]
  (first (b/validate
           params
           :email [[#(not (user-exists? %)) :message "User name already exists"]]
           :password [v/required
                      [v/min-count 8]
                      [= (:password-repeat params) :message "Passwords do not match"]])))

(defn save-user!
  [params]
  (db/create_user!
    (update-in
      (select-keys params [:email :password])
      [:password]
      hashers/encrypt {:algorithm :pbkdf2+sha256})))


(defn user-signup
  [{:keys [params]}]
  (if-let [errors (validate-user-signup params)]
    (-> (redirect "/user-signup")
        (assoc :flash (assoc params :errors errors)))
    (do
      (save-user! params)
      (-> (redirect "/accounts-list")
          (assoc :flash (select-keys params [:email]))
          (assoc :session {:identity (:email params)})))))

(defn accounts-list-page
  [request]
  (if-let [identity (:identity request)]
    (layout/render
    "accounts-list.html"
    (let [user {:email identity}
          accounts (db/accounts_for_user user)]
      (if (not-empty accounts)
        (merge user {:accounts accounts})
        user)))
    (-> (redirect "/user-login")
        (assoc :flash {:warning "Please login first"} ))
    ))


(defn account-exists?
  [account_name]
  (:exists (first (db/exists_account? {:account_name account_name}))))

(defn validate-account-creation [params]
  (first
    (b/validate params
                :account_name [v/required
                               [#(not (account-exists? %)) :message "Account name already exists"]
                               [v/min-count 6]
                               [v/matches #"^[a-z][\d,a-z,-]+[\d,a-z]$" :message "Account name must be lowercase letters and - only, and start and end with a letter"]])))


(defn save-account!
  [{:keys [params]
    {:keys [account_name]} :params
    {:keys [identity]} :session}]
  (if-let [errors (validate-account-creation params)]
    (-> (redirect "/create-account")
        (assoc :flash (assoc params :errors errors)))
    (do
      (db/create_account! {:account_name account_name})
      (db/give_access! {:account_name account_name :email identity})
      (db/change_admin! {:account_name account_name :email identity})
      (redirect (str "/" account_name "/admin")))))


(defn admin?
  [email account_name]
  (-> {:email email :account_name account_name}
    (db/user_rights_for_account)
    (first)
    (:admin)))

(defn admin-page
  [request]
  (let [identity (:identity request)
        account_name (get-in request [:params :account_name])
        users (db/users_for_account {:account_name account_name})
        admins_number (count (filter #(true? (:admin %)) users))
        admin? (admin? identity account_name)]
    (if (nil? admin?)
      (layout/error-page
        {:status 403
         :title "Not authorized"})
      (-> (layout/render
          "admin.html"
          {:users users
           :account_name account_name
           :admins_number admins_number
           :admin admin?})))))
;; je ne comprends toujours pas pourquoi le assoc-in ne marchait pas !!
;; http://stackoverflow.com/questions/22205501/why-is-my-ring-session-being-reset


(defn change-admin
  [request]
  (let [identity (:identity request)
        account_name (get-in request [:params :account_name])]
    (if (admin? identity account_name)
    (do (db/change_admin! (:params request))
        (redirect (str "/" (get-in request [:params :account_name]) "/admin")))
    (layout/error-page
      {:status 403
       :title "Not authorized"}))))

(defn user-login-page
  [{:keys [flash]}]
  (layout/render
    "user-login.html"
    flash)
  )


(defn validate-user-login
  [params]
  (first
    (b/validate params
                :email [[user-exists? :message "Invalid login/password"]]
                :password [[hashers/check (:password (first (db/get_password (select-keys params [:email])))) :message "Invalid login/password"]])))


(defn user-login
  [{:keys [params]}]
  (if-let [errors (validate-user-login params)]
    (-> (redirect "/user-login")
        (assoc :flash (assoc params :errors errors)))
    (-> (redirect "/accounts-list")
        (assoc :session {:identity (:email params)}))))


(defn home-page
  [request]
  (if (authenticated? request)
    (redirect "/accounts-list")
    (redirect "/user-signup")))

(defn user-logout
  [request]
  (-> (redirect "/")
      (assoc :session {:identity nil})))

(defn add-user
  "If the user is a new one, a random password is already created"
  [request]
  (let [params (:params request)
        identity (:identity request)
        account_name (get-in request [:params :account_name])]
    (if (admin? identity account_name)
      (do
        (when (not (user-exists? (:email params)))
          (save-user! (if (nil? (:password params))
                        (assoc params :password (str (crypto.random/bytes 12)))
                        params)))
        (db/give_access! (select-keys params [:account_name :email]))
        (redirect (str "/" (:account_name params) "/admin")))
      (layout/error-page
        {:status 403
         :title "Not authorized"}))))
;; A faire: ajouter un envoi d'email

;; voir comment mutualiser les authentifications

(defn retrieve-password
  [request]
  (let [email (get-in request [:params :email])]
    (when (user-exists? email)
      (do
        (if (empty? (db/user_has_retrieve_token? {:email email}))
          (db/create_retrieve_token! {:token (url-part 32)
                                      :email email})
          (db/update_retrieve_token! {:token (url-part 32)
                                      :email email}))
        ;;(send email if user exists)
        ))
    (assoc (redirect "/retrieve-password") :flash {:sent true})))

(defn retrieve-password-page
  [{:keys [flash]}]
  (layout/render
    "retrieve-password.html"
    (select-keys flash [:sent])))



(defn valid-token?
  [token]
  (let [token-map (first (db/token_details_for_retrieve_email {:token token}))
        timestamp (c/from-date (:created_at token-map))
        now (l/local-now)
        difference-in-minutes (t/in-minutes (t/interval timestamp now))]
    (and
      (not (empty? token-map))
      (< difference-in-minutes 30))))


(defn reset-password
  [request]
  (let [params (:params request)
        token (:token params)
        email (:email (first (db/token_details_for_retrieve_email {:token token})))]
    (if-let [errors (first (b/validate params
                                     :password [v/required
                                                [v/min-count 8]
                                                [= (:password-repeat params) :message "Passwords do not match"]]
                                      :token [[valid-token? :meassage "Token does not exist"]] ))]
    (assoc (redirect (str "/reset-password/" token)) :flash {:errors errors})
    (do
      (db/update_password! {:email email
                            :password (hashers/encrypt (:password params) {:algorithm :pbkdf2+sha256})})
      (-> (redirect (str "/reset-password/" token))
          (assoc :flash {:updated true} :session {:identity email}))))))





(defn reset-password-page
  [request]
  (let [errors (get-in request [:flash :errors])
        updated (get-in request [:flash :updated])
        token (get-in request [:params :token])]
    (if (valid-token? token)
      (layout/render
        "reset-password.html"
        {:errors errors :updated updated :token token})
      (layout/error-page
        {:status 403
         :title "Token does not exist"}))))


;(defn mytest [handler request]
;  (str {:pouet (macroexpand (handler request))}))



(defroutes home-routes
           (GET "/" request (home-page request))
           (GET "/user-signup" request (user-signup-page request))
           (POST "/user-signup" request (user-signup request))
           (GET "/accounts-list" request (accounts-list-page request))
           (POST "/create-account" request (save-account! request))
           (GET "/:account_name/admin" request (admin-page request))
           (GET "/user-login" request (user-login-page request))
           (POST "/user-login" request (user-login request))
           (GET "/user-logout" request (user-logout request))
           (POST "/:account_name/admin/add-user" request (add-user request))
           (POST "/:account_name/admin/change-admin" request (change-admin request))
           (GET "/retrieve-password" request (retrieve-password-page request))
           (POST "/retrieve-password" request (retrieve-password request))
           (GET "/reset-password/:token" request (reset-password-page request))
           (POST "/reset-password/:token" request (reset-password request))


           ;generaliser la fonction de logout + mettre le lien dans le template de base avec test d'authentification
           (GET "/test" request "tutu")
           (GET "/test2" request (str (valid-token? "j-OP8auCDaYq40-0-UB7pGLSZKt0IL4oUCV4hc8D9rc")))

           )