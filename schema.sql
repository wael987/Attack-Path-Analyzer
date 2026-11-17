--
-- PostgreSQL database dump
--

\restrict d5Uf9LlH3fXIntGo9kEI0I3bA58ee8bUjKRQFRp7kd1K6cgvPe4OVT50vL8IobQ

-- Dumped from database version 16.15 (Ubuntu 16.15-0ubuntu0.24.04.1)
-- Dumped by pg_dump version 16.15 (Ubuntu 16.15-0ubuntu0.24.04.1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: edge_vulnerabilities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.edge_vulnerabilities (
    edge_id integer NOT NULL,
    vulnerability_id integer NOT NULL,
    validation_status character varying(20) DEFAULT 'hypothetical'::character varying NOT NULL,
    CONSTRAINT edge_vulnerabilities_validation_status_check CHECK (((validation_status)::text = ANY ((ARRAY['hypothetical'::character varying, 'validated'::character varying, 'rejected'::character varying])::text[])))
);


--
-- Name: hosts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.hosts (
    host_id character varying(20) NOT NULL,
    hostname character varying(100) NOT NULL,
    ip_address inet NOT NULL,
    role character varying(50) NOT NULL,
    criticality character varying(20) NOT NULL
);


--
-- Name: network_edges; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.network_edges (
    edge_id integer NOT NULL,
    source_host character varying(20) NOT NULL,
    target_host character varying(20) NOT NULL,
    relationship character varying(50) NOT NULL,
    reachable boolean NOT NULL,
    exploitable character varying(20) DEFAULT 'not_verified'::character varying NOT NULL,
    evidence text,
    CONSTRAINT network_edges_exploitable_check CHECK (((exploitable)::text = ANY ((ARRAY['not_verified'::character varying, 'verified'::character varying, 'not_exploitable'::character varying])::text[])))
);


--
-- Name: network_edges_edge_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.network_edges_edge_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: network_edges_edge_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.network_edges_edge_id_seq OWNED BY public.network_edges.edge_id;


--
-- Name: vulnerabilities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vulnerabilities (
    vulnerability_id integer NOT NULL,
    host_id character varying(20) NOT NULL,
    port integer,
    service character varying(100),
    vulnerability_name character varying(200) NOT NULL,
    cve_id character varying(30),
    cvss_score numeric(3,1),
    verification_status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    evidence text,
    CONSTRAINT vulnerabilities_cvss_score_check CHECK (((cvss_score >= (0)::numeric) AND (cvss_score <= (10)::numeric))),
    CONSTRAINT vulnerabilities_port_check CHECK (((port >= 1) AND (port <= 65535))),
    CONSTRAINT vulnerabilities_verification_status_check CHECK (((verification_status)::text = ANY ((ARRAY['pending'::character varying, 'confirmed'::character varying, 'not_confirmed'::character varying])::text[])))
);


--
-- Name: vulnerabilities_vulnerability_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.vulnerabilities_vulnerability_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: vulnerabilities_vulnerability_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.vulnerabilities_vulnerability_id_seq OWNED BY public.vulnerabilities.vulnerability_id;


--
-- Name: network_edges edge_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.network_edges ALTER COLUMN edge_id SET DEFAULT nextval('public.network_edges_edge_id_seq'::regclass);


--
-- Name: vulnerabilities vulnerability_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vulnerabilities ALTER COLUMN vulnerability_id SET DEFAULT nextval('public.vulnerabilities_vulnerability_id_seq'::regclass);


--
-- Name: edge_vulnerabilities edge_vulnerabilities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.edge_vulnerabilities
    ADD CONSTRAINT edge_vulnerabilities_pkey PRIMARY KEY (edge_id, vulnerability_id);


--
-- Name: hosts hosts_ip_address_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.hosts
    ADD CONSTRAINT hosts_ip_address_key UNIQUE (ip_address);


--
-- Name: hosts hosts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.hosts
    ADD CONSTRAINT hosts_pkey PRIMARY KEY (host_id);


--
-- Name: network_edges network_edges_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.network_edges
    ADD CONSTRAINT network_edges_pkey PRIMARY KEY (edge_id);


--
-- Name: network_edges network_edges_source_host_target_host_relationship_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.network_edges
    ADD CONSTRAINT network_edges_source_host_target_host_relationship_key UNIQUE (source_host, target_host, relationship);


--
-- Name: vulnerabilities vulnerabilities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vulnerabilities
    ADD CONSTRAINT vulnerabilities_pkey PRIMARY KEY (vulnerability_id);


--
-- Name: edge_vulnerabilities edge_vulnerabilities_edge_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.edge_vulnerabilities
    ADD CONSTRAINT edge_vulnerabilities_edge_id_fkey FOREIGN KEY (edge_id) REFERENCES public.network_edges(edge_id);


--
-- Name: edge_vulnerabilities edge_vulnerabilities_vulnerability_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.edge_vulnerabilities
    ADD CONSTRAINT edge_vulnerabilities_vulnerability_id_fkey FOREIGN KEY (vulnerability_id) REFERENCES public.vulnerabilities(vulnerability_id);


--
-- Name: network_edges network_edges_source_host_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.network_edges
    ADD CONSTRAINT network_edges_source_host_fkey FOREIGN KEY (source_host) REFERENCES public.hosts(host_id);


--
-- Name: network_edges network_edges_target_host_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.network_edges
    ADD CONSTRAINT network_edges_target_host_fkey FOREIGN KEY (target_host) REFERENCES public.hosts(host_id);


--
-- Name: vulnerabilities vulnerabilities_host_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vulnerabilities
    ADD CONSTRAINT vulnerabilities_host_id_fkey FOREIGN KEY (host_id) REFERENCES public.hosts(host_id);


--
-- PostgreSQL database dump complete
--

\unrestrict d5Uf9LlH3fXIntGo9kEI0I3bA58ee8bUjKRQFRp7kd1K6cgvPe4OVT50vL8IobQ

