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
            [crypto.random :refer [url-part]]
            [clj-time.core :as t]
            [clj-time.coerce :as c]
            [clj-time.local :as l]
            [postal.core :as p]
            [environ.core :refer [env]]))

;this is a handler, it takes a request and gives a response
;the response will render a template with an associated context-map

(defn user-signup-page
  [request]
  (layout/render
    "user-signup.html"
    ;(-> request :flash)
    (:flash request)))


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
  (if-let [identity (-> request :session :identity)]
    (layout/render
    "accounts-list.html"
    (let [user {:email identity}]
      (merge user
             (when-let [accounts (not-empty (db/accounts_for_user user))] {:accounts accounts})
             (when-let [errors (get-in request [:flash :errors])] {:errors errors}))))
    (-> (redirect "/user-login")
        (assoc :flash {:warning "Please login first"}))))


(defn create-account-page
  [request]
  (if-let [identity (-> request :session :identity)]
    (layout/render
      "create-account.html"
      (let [user {:email identity}]
        (merge user
               ;(when-let [accounts (not-empty (db/accounts_for_user user))] {:accounts accounts})
               (when-let [errors (get-in request [:flash :errors])] {:errors errors}))))
    (-> (redirect "/user-login")
        (assoc :flash {:warning "Please login first"}))))





(defn account-exists?
  [account_name]
  (:exists (first (db/exists_account? {:account_name account_name}))))

(defn validate-account-creation [params]
  (first
    (b/validate params
                :account_name [v/required
                               [#(not (account-exists? %)) :message "Account name already exists"]
                               [v/min-count 6 :message "Account name must be more than 6 characters"]
                               [v/matches #"^[a-z][\d,a-z,-]+[\d,a-z]$" :message "Account name must be lowercase letters and - only, and start and end with a letter"]])))


(defn save-account!
  [{:keys [params]
    {:keys [account_name]} :params
    {:keys [identity]} :session}]
  (if-let [errors (validate-account-creation params)]
    (-> (redirect  "/create-account")
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
  (let [identity (-> request :session :identity)
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
  (let [identity (-> request :session :identity)
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
  (if (-> request :session :identity)
    (redirect "/accounts-list")
    (layout/render
    "home.html")))

(defn user-logout
  [request]
  (-> (redirect "/")
      (assoc :session {:identity nil})))


(defn create-token
  [email]
  (let [token (url-part 32)]
    (do
      (if (empty? (db/user_has_retrieve_token? {:email email}))
        (db/create_retrieve_token! {:token token
                                    :email email})
        (db/update_retrieve_token! {:token token
                                    :email email}))
      token)))

(def app-url
  ;"http://powerful-retreat-6840.herokuapp.com"
  "http://localhost:3000"
  )

(def smtp-settings {:host (env :smtp-host)
                    :user (env :smtp-user)
                    :pass (env :smtp-pass)
                    :ssl :yes!!!11})


(defn add-user
  "If the user is a new one, a random password is created and an email is sent"
  [request]
  (let [params (:params request)
        identity (-> request :session :identity)
        account_name (get-in request [:params :account_name])
        new-user (:email params)]
    (if (admin? identity account_name)
      (do
        (when (not (user-exists? new-user))
          (save-user! {:email new-user :password (str (crypto.random/bytes 12 ))})
          (let [token (create-token new-user)]
            (p/send-message smtp-settings
                            {:from "laurent.test.smtp@gmail.com"
                             :to "laurent.test.smtp@gmail.com"
                             :subject "Your account has been created on Clojure-app"
                             :body (str "An account for your email " new-user " has been created by " identity ". Visit " app-url "/reset-password/" token " to set your password.")})))
        (db/give_access! (select-keys params [:account_name :email]))
        (redirect (str "/" (:account_name params) "/admin")))
      (layout/error-page
        {:status 403
         :title "Not authorized"}))))

;; voir comment mutualiser les authentifications


(defn retrieve-password
  [request]
  (let [email (get-in request [:params :email])]
    (when (user-exists? email)
      (let [token (create-token email)]
        (p/send-message smtp-settings
                        {:from "laurent.test.smtp@gmail.com"
                         :to "laurent.test.smtp@gmail.com"
                         :subject "Reset your password on Clojure-app"
                         :body (str "You requested to reset the password for the account " email ". Visit " app-url "/reset-password/" token " to do this.")})))
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
           (GET "/create-account" request (create-account-page request))

           (GET "/test" request (db/accounts_for_user {:email "laurent@test.com"}))
           )